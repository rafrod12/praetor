"""Tamper-evident audit log.

Every decision the orchestrator makes is appended here. Each entry stores the
hash of the previous entry (a hash chain), so altering or deleting any past
entry breaks the chain and is detected by :meth:`AuditLog.verify`. Periodic
*checkpoints* publish the current head hash; in production these would be
anchored externally (e.g. a public transparency log) so that not even the
operator can rewrite history.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional

GENESIS = "0" * 64


def _hash_entry(prev_hash: str, record: dict) -> str:
    body = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{prev_hash}|{body}".encode("utf-8")).hexdigest()


@dataclass
class AuditEntry:
    index: int
    timestamp: float
    agent_id: str
    action: str
    resource: str
    tier: str
    decision: str            # approved | denied
    reason: str
    signers: List[str] = field(default_factory=list)
    digest: str = ""
    prev_hash: str = GENESIS
    entry_hash: str = ""

    def record_body(self) -> dict:
        """The portion of the entry that the hash commits to."""
        d = asdict(self)
        d.pop("entry_hash", None)
        return d

    def recompute_hash(self) -> str:
        return _hash_entry(self.prev_hash, self.record_body())


@dataclass
class Checkpoint:
    index: int
    head_hash: str
    timestamp: float


class AuditLog:
    """An append-only, hash-chained log held in memory (and optionally on disk)."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.entries: List[AuditEntry] = []
        self.checkpoints: List[Checkpoint] = []
        self.path = path

    @property
    def head_hash(self) -> str:
        return self.entries[-1].entry_hash if self.entries else GENESIS

    def append(
        self,
        *,
        agent_id: str,
        action: str,
        resource: str,
        tier: str,
        decision: str,
        reason: str,
        signers: Optional[List[str]] = None,
        digest: str = "",
    ) -> AuditEntry:
        entry = AuditEntry(
            index=len(self.entries),
            timestamp=time.time(),
            agent_id=agent_id,
            action=action,
            resource=resource,
            tier=tier,
            decision=decision,
            reason=reason,
            signers=list(signers or []),
            digest=digest,
            prev_hash=self.head_hash,
        )
        entry.entry_hash = entry.recompute_hash()
        self.entries.append(entry)
        if self.path:
            self._persist(entry)
        return entry

    def checkpoint(self) -> Checkpoint:
        cp = Checkpoint(index=len(self.entries) - 1, head_hash=self.head_hash, timestamp=time.time())
        self.checkpoints.append(cp)
        return cp

    def verify(self) -> "VerifyResult":
        """Recompute the whole chain and report the first break, if any."""
        prev = GENESIS
        for i, entry in enumerate(self.entries):
            if entry.index != i:
                return VerifyResult(False, i, "index out of order")
            if entry.prev_hash != prev:
                return VerifyResult(False, i, "prev_hash does not match previous entry")
            if entry.recompute_hash() != entry.entry_hash:
                return VerifyResult(False, i, "entry contents have been altered")
            prev = entry.entry_hash

        for cp in self.checkpoints:
            if cp.index < len(self.entries) and self.entries[cp.index].entry_hash != cp.head_hash:
                return VerifyResult(False, cp.index, "checkpoint head hash mismatch")

        return VerifyResult(True, -1, "chain intact")

    def _persist(self, entry: AuditEntry) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(entry)) + "\n")


@dataclass
class VerifyResult:
    ok: bool
    broken_index: int
    detail: str

    def __bool__(self) -> bool:
        return self.ok
