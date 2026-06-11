"""Risk policy: which agent actions require threshold co-signing.

Praetor uses *tiered consensus* so the expensive m-of-n path stays off the hot
path. Routine, low-risk actions are served with short-lived capability tokens
(locally verifiable, no round trip). Consequential actions are fanned out to
the signing nodes for co-signature, and the most consequential (CRITICAL)
require a larger quorum than ordinary HIGH-risk actions.

Design decisions (see SECURITY.md for the full rationale):

* **Deterministic policy blocks; scoring only escalates.** Optional advisory
  scorers (heuristics or ML) may raise a LOW classification to HIGH, but can
  never lower a tier or approve anything. The blocking decision is always
  reproducible from the static policy.
* **Default-deny.** An unknown action type is HIGH risk (fail-closed), not
  waved through.
* **Escalation by impact.** Payments/transfers above ``critical_amount`` and
  inherently irreversible administrative actions are CRITICAL and require a
  larger quorum (threshold + 1).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class RiskTier(str, Enum):
    LOW = "low"            # capability-token path
    HIGH = "high"          # threshold co-sign path (m-of-n)
    CRITICAL = "critical"  # escalated co-sign path (m+1-of-n)
    DENY = "deny"          # statically forbidden


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
    # expanded catalog (launch-feedback research): externally-visible or
    # state-mutating actions agents commonly perform in production.
    "write",
    "update",
    "execute",
    "send_email",
    "post",
    "purchase",
    "subscribe",
    "create_key",
    "modify_permissions",
    "create_user",
}

# Critical action types: irreversible AND privilege/infrastructure-shaping.
# These require an escalated quorum (threshold + 1).
CRITICAL_RISK_ACTIONS = {
    "grant_access",
    "modify_permissions",
    "create_key",
    "create_user",
    "deploy",
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

# An advisory scorer maps (action, resource, metadata) -> risk score in [0, 1].
Scorer = Callable[[str, str, dict], float]


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

    ``critical_amount``: payments/transfers at or above this amount escalate
    from HIGH to CRITICAL.

    ``scorers``: optional advisory risk scorers. If any scorer returns a score
    >= ``escalate_at`` for a LOW action, the action escalates to HIGH. Scorers
    can never de-escalate or approve; the deterministic tables above remain
    the blocking decision.
    """

    threshold: int = 3
    rules: list[Rule] = field(default_factory=list)
    critical_amount: float = 10_000.0
    scorers: list[Scorer] = field(default_factory=list)
    escalate_at: float = 0.8

    def classify(self, action: str, resource: str = "", metadata: Optional[dict] = None) -> "Classification":
        act = (action or "").strip().lower()
        md = metadata or {}

        for rule in self.rules:
            if rule.matches(resource):
                return Classification(act, resource, rule.tier, f"rule:{rule.pattern} {rule.reason}".strip())

        if act in FORBIDDEN_ACTIONS:
            return Classification(act, resource, RiskTier.DENY, "statically forbidden action")

        if act in CRITICAL_RISK_ACTIONS:
            return Classification(act, resource, RiskTier.CRITICAL, "critical action type")

        if act in HIGH_RISK_ACTIONS:
            # Impact-based escalation: large money movement is CRITICAL.
            amount = self._numeric_amount(md)
            if act in {"payment", "transfer", "purchase"} and amount is not None and amount >= self.critical_amount:
                return Classification(
                    act, resource, RiskTier.CRITICAL,
                    f"amount {amount:g} >= critical threshold {self.critical_amount:g}",
                )
            return Classification(act, resource, RiskTier.HIGH, "high-risk action type")

        if act in LOW_RISK_ACTIONS:
            score = self._advisory_score(act, resource, md)
            if score is not None and score >= self.escalate_at:
                # Advisory escalation: scoring may only raise the tier.
                return Classification(
                    act, resource, RiskTier.HIGH,
                    f"advisory scorer escalated (score={score:.2f})",
                    advisory_score=score,
                )
            return Classification(act, resource, RiskTier.LOW, "low-risk action type",
                                  advisory_score=score)

        # Unknown -> fail closed.
        return Classification(act, resource, RiskTier.HIGH, "unknown action type (fail-closed)")

    def required_signatures(self, tier: "RiskTier", node_count: int) -> int:
        """How many co-signatures a given tier needs.

        Deliberately NOT capped at ``node_count``: a cluster too small (or too
        degraded) to field the escalated quorum simply cannot approve critical
        actions -- fail-closed. Operators should run n >= threshold + 2.
        """
        if tier is RiskTier.CRITICAL:
            return self.threshold + 1
        return self.threshold

    # ----- internals ----------------------------------------------------

    @staticmethod
    def _numeric_amount(metadata: dict) -> Optional[float]:
        amount = metadata.get("amount")
        if isinstance(amount, (int, float)) and not isinstance(amount, bool):
            return float(amount)
        return None

    def _advisory_score(self, action: str, resource: str, metadata: dict) -> Optional[float]:
        if not self.scorers:
            return None
        best = 0.0
        for scorer in self.scorers:
            try:
                best = max(best, min(1.0, max(0.0, float(scorer(action, resource, metadata)))))
            except Exception:
                # A broken scorer must never break mediation; advisory only.
                continue
        return best


@dataclass
class Classification:
    action: str
    resource: str
    tier: RiskTier
    reason: str
    advisory_score: Optional[float] = None

    @property
    def requires_quorum(self) -> bool:
        return self.tier in (RiskTier.HIGH, RiskTier.CRITICAL)


def classify(action: str, resource: str = "", policy: Optional[Policy] = None,
             metadata: Optional[dict] = None) -> Classification:
    """Module-level convenience wrapper."""
    return (policy or Policy()).classify(action, resource, metadata)
