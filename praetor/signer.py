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
    def __init__(self, node_id: str, policy: Optional[Policy] = None) -> None:
        self.key = SignerKey.generate(node_id)
        self.node_id = node_id
        self.policy = policy or Policy()

    @property
    def public_key_hex(self) -> str:
        return self.key.public_key_hex()

    def co_sign(self, action_payload: dict) -> SignResult:
        """Independently validate and (maybe) sign a high-risk action.

        ``action_payload`` is the canonical action description shared by the
        orchestrator with every node. All nodes hash the same payload so their
        signatures verify against one digest.
        """
        action = action_payload.get("action", "")
        resource = action_payload.get("resource", "")
        cls = self.policy.classify(action, resource)

        if cls.tier is RiskTier.DENY:
            return SignResult(self.node_id, False, None, f"{self.node_id} refuses: {cls.reason}")

        # A correct node only co-signs things that are actually high-risk
        # actions routed for quorum; it would not sign a deny-listed action.
        digest = canonical_digest(action_payload)
        signature = self.key.sign(digest)
        return SignResult(self.node_id, True, signature, f"{self.node_id} co-signed ({cls.reason})")
