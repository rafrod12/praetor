"""The Praetor orchestrator: the non-bypassable broker.

Every agent action is mediated here. The orchestrator never makes a unilateral
high-risk decision -- it fans the action out to the signing nodes and acts only
on the collected quorum of co-signatures. Every decision (approve or deny) is
appended to the tamper-evident audit log, and the log head can be periodically
co-signed by the nodes and anchored externally.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .anchor import Anchor, SignedCheckpoint
from .audit import AuditLog
from .crypto import ThresholdQuorum, canonical_digest, verify as verify_sig
from .policy import Policy, RiskTier
from .signer import SignerNode

# Metadata keys whose values are policy-relevant and therefore shared with
# (and committed to by) every signing node. Everything else stays metadata-only.
RISK_FACTOR_KEYS = ("amount", "currency")


@dataclass
class Capability:
    """A short-lived, single-scope token for routine low-risk actions.

    When the requesting agent has a registered public key, the token is
    *sender-constrained* (DPoP-style): redemption requires a fresh signature
    by the agent's key over the redemption payload, so a stolen token is
    useless without the agent's private key.
    """

    token: str
    agent_id: str
    action: str
    resource: str
    expires_at: float
    agent_pubkey: Optional[str] = None  # hex; None = unbound (no key registered)

    def valid_for(self, agent_id: str, action: str, resource: str) -> bool:
        return (
            time.time() < self.expires_at
            and self.agent_id == agent_id
            and self.action == action
            and self.resource == resource
        )


def redemption_payload(token: str, agent_id: str, action: str, resource: str) -> dict:
    """The canonical payload an agent signs to prove possession on redemption."""
    return {"purpose": "redeem", "token": token, "agent_id": agent_id,
            "action": action, "resource": resource}


@dataclass
class Decision:
    approved: bool
    tier: str
    reason: str
    signers: List[str] = field(default_factory=list)
    capability: Optional[str] = None
    audit_index: int = -1
    audit_hash: str = ""
    advisory_score: Optional[float] = None


class Orchestrator:
    def __init__(
        self,
        nodes: Optional[List[SignerNode]] = None,
        threshold: int = 3,
        node_count: int = 5,
        policy: Optional[Policy] = None,
        audit_path: Optional[str] = None,
        capability_ttl: float = 30.0,
        anchor: Optional[Anchor] = None,
        anchor_every: int = 0,
    ) -> None:
        self.policy = policy or Policy(threshold=threshold)
        if nodes is None:
            nodes = [SignerNode(f"node-{i+1}", policy=self.policy) for i in range(node_count)]
        self.nodes: List[SignerNode] = nodes
        self.threshold = threshold
        self.quorum = ThresholdQuorum(
            threshold=threshold,
            registry={n.node_id: n.public_key_hex for n in self.nodes},
        )
        self.audit = AuditLog(path=audit_path)
        self.capability_ttl = capability_ttl
        self._capabilities: Dict[str, Capability] = {}
        self._agents: Dict[str, str] = {}  # agent_id -> public key hex
        self.anchor = anchor
        self.anchor_every = anchor_every

    # ----- agent identity -------------------------------------------------

    def register_agent(self, agent_id: str, public_key_hex: str) -> None:
        """Register (or rotate) an agent's public key.

        Once registered, every capability issued to this agent is bound to the
        key and redemption requires proof of possession.
        """
        self._agents[agent_id] = public_key_hex

    def agent_key(self, agent_id: str) -> Optional[str]:
        return self._agents.get(agent_id)

    # ----- public API ---------------------------------------------------

    def request_action(
        self,
        agent_id: str,
        action: str,
        resource: str = "",
        metadata: Optional[dict] = None,
    ) -> Decision:
        """Mediate a single agent action. This is the only path to action."""
        md = metadata or {}
        cls = self.policy.classify(action, resource, md)

        if cls.tier is RiskTier.DENY:
            return self._deny(agent_id, action, resource, "deny", cls.reason)

        if cls.tier is RiskTier.LOW:
            return self._issue_capability(agent_id, action, resource, cls.reason, cls.advisory_score)

        # HIGH or CRITICAL -> threshold co-sign (CRITICAL needs a larger quorum).
        return self._threshold_authorize(agent_id, action, resource, md, cls)

    def redeem_capability(
        self,
        token: str,
        agent_id: str,
        action: str,
        resource: str,
        proof: Optional[str] = None,
    ) -> bool:
        """Redeem a single-use capability.

        For tokens bound to an agent key, ``proof`` must be the agent's hex
        signature over :func:`redemption_payload`. Unbound tokens (agent never
        registered a key) redeem as before.
        """
        cap = self._capabilities.get(token)
        if cap is None or not cap.valid_for(agent_id, action, resource):
            return False
        if cap.agent_pubkey is not None:
            if not proof:
                return False
            digest = canonical_digest(redemption_payload(token, agent_id, action, resource))
            if not verify_sig(cap.agent_pubkey, digest, proof):
                return False
        # single-use
        del self._capabilities[token]
        return True

    def checkpoint_and_anchor(self) -> Optional[SignedCheckpoint]:
        """Have the nodes co-sign the current log head and publish it.

        Returns the signed checkpoint, or None when no anchor is configured.
        """
        if self.anchor is None:
            return None
        cp = SignedCheckpoint(
            index=len(self.audit.entries) - 1,
            head_hash=self.audit.head_hash,
            timestamp=time.time(),
        )
        payload = cp.payload()
        for node in self.nodes:
            result = node.sign_checkpoint(payload)
            if result.signed and result.signature:
                cp.signatures[result.node_id] = result.signature
        self.audit.checkpoint()
        self.anchor.publish(cp)
        return cp

    # ----- internals ----------------------------------------------------

    def _maybe_auto_anchor(self) -> None:
        if (
            self.anchor is not None
            and self.anchor_every > 0
            and len(self.audit.entries) % self.anchor_every == 0
        ):
            self.checkpoint_and_anchor()

    def _issue_capability(
        self, agent_id: str, action: str, resource: str, reason: str,
        advisory_score: Optional[float] = None,
    ) -> Decision:
        token = secrets.token_urlsafe(24)
        bound_key = self._agents.get(agent_id)
        self._capabilities[token] = Capability(
            token=token,
            agent_id=agent_id,
            action=action,
            resource=resource,
            expires_at=time.time() + self.capability_ttl,
            agent_pubkey=bound_key,
        )
        bound = "sender-bound" if bound_key else "unbound"
        entry = self.audit.append(
            agent_id=agent_id,
            action=action,
            resource=resource,
            tier=RiskTier.LOW.value,
            decision="approved",
            reason=f"capability issued, {bound} ({reason})",
        )
        self._maybe_auto_anchor()
        return Decision(
            approved=True,
            tier=RiskTier.LOW.value,
            reason=reason,
            capability=token,
            audit_index=entry.index,
            audit_hash=entry.entry_hash,
            advisory_score=advisory_score,
        )

    def _threshold_authorize(
        self, agent_id: str, action: str, resource: str, metadata: dict, cls
    ) -> Decision:
        required = self.policy.required_signatures(cls.tier, self.quorum.n())

        # Canonical payload every node co-signs. Policy-relevant scalars are
        # shared as risk_factors so each node re-derives the tier itself;
        # everything else stays metadata-only (keys, not values).
        risk_factors = {k: metadata[k] for k in RISK_FACTOR_KEYS if k in metadata}
        action_payload = {
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "nonce": secrets.token_hex(8),
            "ts": int(time.time()),
            "risk_factors": risk_factors,
            "metadata_keys": sorted(metadata.keys()),
        }
        digest = canonical_digest(action_payload)

        signatures: Dict[str, str] = {}
        for node in self.nodes:
            result = node.co_sign(action_payload)
            if result.signed and result.signature:
                signatures[node.node_id] = result.signature

        valid_signers = list(self.quorum.valid_signers(digest, signatures))
        if len(valid_signers) >= required:
            entry = self.audit.append(
                agent_id=agent_id,
                action=action,
                resource=resource,
                tier=cls.tier.value,
                decision="approved",
                reason=f"{len(valid_signers)}-of-{self.quorum.n()} co-signed (required {required})",
                signers=valid_signers,
                digest=digest.hex(),
            )
            self._maybe_auto_anchor()
            return Decision(
                approved=True,
                tier=cls.tier.value,
                reason=f"quorum reached ({len(valid_signers)}/{required} required)",
                signers=valid_signers,
                audit_index=entry.index,
                audit_hash=entry.entry_hash,
            )

        return self._deny(
            agent_id,
            action,
            resource,
            cls.tier.value,
            f"quorum not reached ({len(valid_signers)}/{required})",
            signers=valid_signers,
            digest=digest.hex(),
        )

    def _deny(
        self,
        agent_id: str,
        action: str,
        resource: str,
        tier: str,
        reason: str,
        signers: Optional[List[str]] = None,
        digest: str = "",
    ) -> Decision:
        entry = self.audit.append(
            agent_id=agent_id,
            action=action,
            resource=resource,
            tier=tier,
            decision="denied",
            reason=reason,
            signers=signers or [],
            digest=digest,
        )
        self._maybe_auto_anchor()
        return Decision(
            approved=False,
            tier=tier,
            reason=reason,
            signers=signers or [],
            audit_index=entry.index,
            audit_hash=entry.entry_hash,
        )
