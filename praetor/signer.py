"""A single signing node of the segmented orchestrator.

Each node independently re-applies policy to the action it is asked to
co-sign. It signs *only* if its own policy check passes. Because nodes decide
independently, an attacker must compromise a threshold of them to forge an
approval -- and any node may refuse, providing defense in depth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .crypto import SignerKey, canonical_digest
from .policy import Policy, RiskTier


@dataclass
class SignResult:
    node_id: str
    signed: bool
    signature: Optional[str]
    reason: str


class SignerNode:
    def __init__(self, node_id: str, policy: Optional[Policy] = None,
                 key: Optional[SignerKey] = None) -> None:
        self.key = key or SignerKey.generate(node_id)
        self.node_id = node_id
        self.policy = policy or Policy()

    @property
    def public_key_hex(self) -> str:
        return self.key.public_key_hex()

    def co_sign(self, action_payload: dict) -> SignResult:
        """Independently validate and (maybe) sign a high-risk action.

        ``action_payload`` is the canonical action description shared by the
        orchestrator with every node. All nodes hash the same payload so their
        signatures verify against one digest. ``risk_factors`` carries the
        policy-relevant scalars (e.g. amount) so each node can re-derive the
        tier on its own rather than trusting the orchestrator's claim.
        """
        action = action_payload.get("action", "")
        resource = action_payload.get("resource", "")
        risk_factors = action_payload.get("risk_factors") or {}
        cls = self.policy.classify(action, resource, risk_factors)

        if cls.tier is RiskTier.DENY:
            return SignResult(self.node_id, False, None, f"{self.node_id} refuses: {cls.reason}")

        if not cls.requires_quorum:
            # A correct node only co-signs actions that actually belong on the
            # quorum path; it will not lend its signature to routine actions.
            return SignResult(
                self.node_id, False, None,
                f"{self.node_id} refuses: {cls.tier.value} tier does not need a co-signature",
            )

        digest = canonical_digest(action_payload)
        signature = self.key.sign(digest)
        return SignResult(self.node_id, True, signature, f"{self.node_id} co-signed ({cls.reason})")

    def sign_checkpoint(self, checkpoint_payload: dict) -> SignResult:
        """Co-sign an audit-log checkpoint (head hash attestation).

        Checkpoint signing lets external parties verify that a quorum of
        nodes saw a given log head at a given index -- the building block for
        external anchoring.
        """
        digest = canonical_digest(checkpoint_payload)
        return SignResult(
            self.node_id, True, self.key.sign(digest),
            f"{self.node_id} attested checkpoint",
        )
