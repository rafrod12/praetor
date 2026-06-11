"""Agent-facing SDK.

Integration is meant to be one line at the action boundary: instead of an agent
calling a tool directly, it calls ``client.guarded(...)``. If Praetor approves,
the supplied callable runs; otherwise it is blocked. This is how Praetor stays
*non-bypassable* in practice -- the action only happens through the broker.

Every client owns an Ed25519 identity. The orchestrator binds capability
tokens to that identity (sender-constrained, DPoP-style), so a leaked token is
useless without the agent's private key.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .crypto import SignerKey, canonical_digest
from .orchestrator import Decision, Orchestrator, redemption_payload


class PraetorDenied(Exception):
    """Raised when an action is blocked by Praetor."""

    def __init__(self, decision: Decision) -> None:
        super().__init__(f"Praetor denied [{decision.tier}]: {decision.reason}")
        self.decision = decision


@dataclass
class AgentIdentity:
    """An agent's Ed25519 keypair, used to prove possession of capabilities."""

    agent_id: str
    _key: SignerKey = field(repr=False, default=None)  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self._key is None:
            self._key = SignerKey.generate(self.agent_id)

    @property
    def public_key_hex(self) -> str:
        return self._key.public_key_hex()

    def prove(self, payload: dict) -> str:
        """Sign a canonical payload, returning the hex signature."""
        return self._key.sign(canonical_digest(payload))


@dataclass
class PraetorClient:
    """A thin client bound to an agent identity.

    In a deployment this would talk to the orchestrator over HTTP; here it can
    wrap an in-process :class:`Orchestrator` for tests and the local demo.
    On construction the client registers its public key with the orchestrator,
    after which every capability it receives is sender-bound.
    """

    agent_id: str
    orchestrator: Orchestrator
    identity: Optional[AgentIdentity] = None

    def __post_init__(self) -> None:
        if self.identity is None:
            self.identity = AgentIdentity(self.agent_id)
        self.orchestrator.register_agent(self.agent_id, self.identity.public_key_hex)

    def request(self, action: str, resource: str = "", metadata: Optional[dict] = None) -> Decision:
        return self.orchestrator.request_action(self.agent_id, action, resource, metadata)

    def guarded(
        self,
        action: str,
        resource: str,
        perform: Callable[[], Any],
        metadata: Optional[dict] = None,
    ) -> Any:
        """Authorize then perform an action; raise if denied."""
        decision = self.request(action, resource, metadata)
        if not decision.approved:
            raise PraetorDenied(decision)

        if decision.capability:
            # Low-risk path: redeem the single-use token at the action
            # boundary, proving possession of the agent's key.
            proof = self.identity.prove(
                redemption_payload(decision.capability, self.agent_id, action, resource)
            )
            ok = self.orchestrator.redeem_capability(
                decision.capability, self.agent_id, action, resource, proof=proof
            )
            if not ok:
                raise PraetorDenied(decision)

        return perform()
