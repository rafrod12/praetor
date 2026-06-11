"""Praetor - a distributed, agent-aware reference monitor.

Every consequential agent action is brokered through an orchestrator that is
split across signing nodes. High-risk actions require an m-of-n threshold of
node co-signatures (critical actions need m+1); routine actions use
sender-bound, single-use capability tokens. Every decision is written to a
tamper-evident audit log whose head can be quorum-signed and anchored
externally.

Tagline: "Every agent action, co-signed and accounted for."
"""

from .anchor import FileAnchor, MemoryAnchor, SignedCheckpoint, verify_anchored
from .audit import AuditLog, AuditEntry
from .crypto import SignerKey, ThresholdQuorum
from .orchestrator import Orchestrator, Decision
from .policy import Policy, RiskTier, classify
from .sdk import AgentIdentity, PraetorClient
from .signer import SignerNode

__all__ = [
    "AgentIdentity",
    "AuditEntry",
    "AuditLog",
    "Decision",
    "FileAnchor",
    "MemoryAnchor",
    "Orchestrator",
    "Policy",
    "PraetorClient",
    "RiskTier",
    "SignedCheckpoint",
    "SignerKey",
    "SignerNode",
    "ThresholdQuorum",
    "classify",
    "verify_anchored",
]

__version__ = "0.2.0"
