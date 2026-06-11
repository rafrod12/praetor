"""Risk policy: which agent actions require threshold co-signing.

Praetor uses *tiered consensus* so the expensive m-of-n path stays off the hot
path. Routine, low-risk actions are served with short-lived capability tokens
(locally verifiable, no round trip). Only consequential actions are fanned out
to the signing nodes for co-signature.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskTier(str, Enum):
    LOW = "low"      # capability-token path
    HIGH = "high"    # threshold co-sign path
    DENY = "deny"    # statically forbidden


# High-risk action types: the irreversible / externally-visible / sensitive set.
HIGH_RISK_ACTIONS = {
    "payment",
    "transfer",
    "delete",
    "drop",
    "external_tool",
    "mcp_call",
    "agent_message",
    "secret_access",
    "deploy",
    "grant_access",
}

# Low-risk action types: safe, reversible, read-only.
LOW_RISK_ACTIONS = {
    "read",
    "get",
    "list",
    "search",
    "lookup",
    "status",
}

# Actions that are never allowed regardless of quorum.
FORBIDDEN_ACTIONS = {
    "disable_audit",
    "rotate_root_unilaterally",
}


@dataclass
class Rule:
    """A targeted override. If ``pattern`` matches the resource, force ``tier``."""

    pattern: str
    tier: RiskTier
    reason: str = ""
    _rx: re.Pattern = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._rx = re.compile(self.pattern)

    def matches(self, resource: str) -> bool:
        return bool(self._rx.search(resource or ""))


@dataclass
class Policy:
    """Classifies an action into a :class:`RiskTier`.

    Default-deny posture: an *unknown* action type is treated as HIGH risk
    (fail-closed) rather than waved through.
    """

    threshold: int = 3
    rules: list[Rule] = field(default_factory=list)

    def classify(self, action: str, resource: str = "") -> "Classification":
        act = (action or "").strip().lower()

        for rule in self.rules:
            if rule.matches(resource):
                return Classification(act, resource, rule.tier, f"rule:{rule.pattern} {rule.reason}".strip())

        if act in FORBIDDEN_ACTIONS:
            return Classification(act, resource, RiskTier.DENY, "statically forbidden action")
        if act in HIGH_RISK_ACTIONS:
            return Classification(act, resource, RiskTier.HIGH, "high-risk action type")
        if act in LOW_RISK_ACTIONS:
            return Classification(act, resource, RiskTier.LOW, "low-risk action type")

        # Unknown -> fail closed.
        return Classification(act, resource, RiskTier.HIGH, "unknown action type (fail-closed)")


@dataclass
class Classification:
    action: str
    resource: str
    tier: RiskTier
    reason: str

    @property
    def requires_quorum(self) -> bool:
        return self.tier is RiskTier.HIGH


def classify(action: str, resource: str = "", policy: Optional[Policy] = None) -> Classification:
    """Module-level convenience wrapper."""
    return (policy or Policy()).classify(action, resource)
