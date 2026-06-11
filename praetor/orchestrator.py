"""The Praetor orchestrator: the non-bypassable broker.

Every agent action is mediated here. The orchestrator never makes a unilateral
high-risk decision -- it fans the action out to the signing nodes and acts only
on the collected quorum of co-signatures. Every decision (approve or deny) is
appended to the tamper-evident audit log.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .audit import AuditLog, AuditEntry
from .crypto import ThresholdQuorum, canonical_digest
from .policy import Policy, RiskTier
from .signer import SignerNode


@dataclass
class Capability:
    """A short-lived, single-scope token for routine low-risk actions."""

    token: str
    agent_id: str
    action: str
    resource: str
    expires_at: float

    def valid_for(self, agent_id: str, action: str, resource: str) -> bool:
        return (
            time.time() < self.expires_at
            and self.agent_id == agent_id
            and self.action == action
            and self.resource == resource
        )


@dataclass
class Decision:
    approved: bool
    tier: str
    reason: str
    signers: List[str] = field(default_factory=list)
    capability: Optional[str] = None
    audit_index: int = -1
    audit_hash: str = ""


class Orchestrator:
    def __init__(
        self,
        nodes: Optional[List[SignerNode]] = None,
        threshold: int = 3,
        node_count: int = 5,
        policy: Optional[Policy] = None,
        audit_path: Optional[str] = None,
        capability_ttl: float = 30.0,
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

    # ----- public API ---------------------------------------------------

    def request_action(
        self,
        agent_id: str,
        action: str,
        resource: str = "",
        metadata: Optional[dict] = None,
    ) -> Decision:
        """Mediate a single agent action. This is the only path to action."""
        cls = self.policy.classify(action, resource)

        if cls.tier is RiskTier.DENY:
            return self._deny(agent_id, action, resource, "deny", cls.reason)

        if cls.tier is RiskTier.LOW:
            return self._issue_capability(agent_id, action, resource, cls.reason)

        # HIGH risk -> threshold co-sign.
        return self._threshold_authorize(agent_id, action, resource, metadata or {}, cls.reason)

    def redeem_capability(self, token: str, agent_id: str, action: str, resource: str) -> bool:
        cap = self._capabilities.get(token)
        if cap is None or not cap.valid_for(agent_id, action, resource):
            return False
        # single-use
        del self._capabilities[token]
        return True

    # ----- internals ----------------------------------------------------

    def _issue_capability(self, agent_id: str, action: str, resource: str, reason: str) -> Decision:
        token = secrets.token_urlsafe(24)
        self._capabilities[token] = Capability(
            token=token,
            agent_id=agent_id,
            action=action,
            resource=resource,
            expires_at=time.time() + self.capability_ttl,
        )
        entry = self.audit.append(
            agent_id=agent_id,
            action=action,
            resource=resource,
            tier=RiskTier.LOW.value,
            decision="approved",
            reason=f"capability issued ({reason})",
        )
        return Decision(
            approved=True,
            tier=RiskTier.LOW.value,
            reason=reason,
            capability=token,
            audit_index=entry.index,
            audit_hash=entry.entry_hash,
        )

    def _threshold_authorize(
        self, agent_id: str, action: str, resource: str, metadata: dict, reason: str
    ) -> Decision:
        # Canonical payload every node co-signs (metadata-only; no raw payload retained).
        action_payload = {
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "nonce": secrets.token_hex(8),
            "ts": int(time.time()),
            "metadata_keys": sorted(metadata.keys()),
        }
        digest = canonical_digest(action_payload)

        signatures: Dict[str, str] = {}
        for node in self.nodes:
            result = node.co_sign(action_payload)
            if result.signed and result.signature:
                signatures[node.node_id] = result.signature

        valid_signers = list(self.quorum.valid_signers(digest, signatures))
        if len(valid_signers) >= self.threshold:
            entry = self.audit.append(
                agent_id=agent_id,
                action=action,
                resource=resource,
                tier=RiskTier.HIGH.value,
                decision="approved",
                reason=f"{len(valid_signers)}-of-{self.quorum.n()} co-signed",
                signers=valid_signers,
                digest=digest.hex(),
            )
            return Decision(
                approved=True,
                tier=RiskTier.HIGH.value,
                reason=f"quorum reached ({len(valid_signers)}/{self.threshold} required)",
                signers=valid_signers,
                audit_index=entry.index,
                audit_hash=entry.entry_hash,
            )

        return self._deny(
            agent_id,
            action,
            resource,
            RiskTier.HIGH.value,
            f"quorum not reached ({len(valid_signers)}/{self.threshold})",
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
        return Decision(
            approved=False,
            tier=tier,
            reason=reason,
            signers=signers or [],
            audit_index=entry.index,
            audit_hash=entry.entry_hash,
        )
