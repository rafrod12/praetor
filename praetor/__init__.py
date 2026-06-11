"""Praetor - a distributed, agent-aware reference monitor.

Every consequential agent action is brokered through an orchestrator that is
split across signing nodes. High-risk actions require an m-of-n threshold of
node co-signatures; routine actions use short-lived capability tokens. Every
decision is written to a tamper-evident, externally verifiable audit log.

Tagline: "Every agent action, co-signed and accounted for."
"""

from .crypto import SignerKey, ThresholdQuorum
from .policy import Policy, RiskTier, classify
from .audit import AuditLog, AuditEntry
from .signer import SignerNode
from .orchestrator import Orchestrator, Decision
from .sdk import PraetorClient

__all__ = [
    "SignerKey",
    "ThresholdQuorum",
    "Policy",
    "RiskTier",
    "classify",
    "AuditLog",
    "AuditEntry",
    "SignerNode",
    "Orchestrator",
    "Decision",
    "PraetorClient",
]

__version__ = "0.1.0"
