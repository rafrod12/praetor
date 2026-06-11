"""External anchoring for the audit log.

A hash chain alone proves *internal* consistency: edit any entry and
``verify()`` catches it. But the log's operator could still truncate the log
and regrow it from the cut. Anchoring closes that hole: a quorum of signer
nodes co-signs periodic *checkpoints* (index + head hash), and the signed
checkpoints are published somewhere the operator does not control -- a file
shipped elsewhere, an HTTP endpoint, a public gist, a transparency service.

Verification then has two legs:
  1. the chain is internally intact (``AuditLog.verify``), and
  2. every anchored checkpoint matches the chain and carries enough valid
     node signatures (``verify_anchored``).

Together: not even the operator can quietly rewrite or truncate history that
has been anchored.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Protocol

from .audit import AuditLog
from .crypto import ThresholdQuorum, canonical_digest


@dataclass
class SignedCheckpoint:
    """A quorum attestation that the log head was ``head_hash`` at ``index``."""

    index: int
    head_hash: str
    timestamp: float
    signatures: Dict[str, str] = field(default_factory=dict)  # node_id -> sig hex

    def payload(self) -> dict:
        """The exact payload every node signed."""
        return {"index": self.index, "head_hash": self.head_hash, "timestamp": self.timestamp}

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "SignedCheckpoint":
        d = json.loads(raw)
        return cls(**d)


class Anchor(Protocol):
    """Anywhere signed checkpoints can be published and read back."""

    def publish(self, checkpoint: SignedCheckpoint) -> None: ...

    def fetch_all(self) -> List[SignedCheckpoint]: ...


class FileAnchor:
    """Append-only JSONL file of signed checkpoints.

    Point this at a path *outside* the orchestrator's blast radius (another
    volume, host, or synced directory) for real anchoring; locally it still
    demonstrates and tests the full verification flow.
    """

    def __init__(self, path: str) -> None:
        self.path = path

    def publish(self, checkpoint: SignedCheckpoint) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(checkpoint.to_json() + "\n")

    def fetch_all(self) -> List[SignedCheckpoint]:
        out: List[SignedCheckpoint] = []
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        out.append(SignedCheckpoint.from_json(line))
        except FileNotFoundError:
            pass
        return out


class MemoryAnchor:
    """In-memory anchor for tests and demos."""

    def __init__(self) -> None:
        self.checkpoints: List[SignedCheckpoint] = []

    def publish(self, checkpoint: SignedCheckpoint) -> None:
        self.checkpoints.append(checkpoint)

    def fetch_all(self) -> List[SignedCheckpoint]:
        return list(self.checkpoints)


class HttpAnchor:
    """POST signed checkpoints to an external endpoint (webhook, gist proxy,
    transparency service). Publishing is fire-and-forget but failures raise so
    the caller can alert -- silent anchoring failures defeat the purpose."""

    def __init__(self, url: str, timeout: float = 5.0) -> None:
        import httpx  # local import: optional dependency path

        self._httpx = httpx
        self.url = url
        self.timeout = timeout
        self._published: List[SignedCheckpoint] = []

    def publish(self, checkpoint: SignedCheckpoint) -> None:
        resp = self._httpx.post(self.url, json=json.loads(checkpoint.to_json()), timeout=self.timeout)
        resp.raise_for_status()
        self._published.append(checkpoint)

    def fetch_all(self) -> List[SignedCheckpoint]:
        # Verification should read from the remote store out-of-band; we keep
        # the local copies so in-process verification still works.
        return list(self._published)


@dataclass
class AnchorVerifyResult:
    ok: bool
    detail: str
    checked: int = 0
    failed_index: Optional[int] = None

    def __bool__(self) -> bool:
        return self.ok


def verify_anchored(
    log: AuditLog,
    anchor: Anchor,
    quorum: ThresholdQuorum,
    required: Optional[int] = None,
) -> AnchorVerifyResult:
    """Verify the log against externally anchored, quorum-signed checkpoints.

    Checks, for every published checkpoint:
      * the checkpoint's signatures are valid for >= ``required`` distinct
        registered nodes (default: the quorum threshold), and
      * the log still contains the anchored head hash at the anchored index.

    A truncated/regrown log fails because the anchored head no longer matches.
    """
    required = required if required is not None else quorum.threshold
    checkpoints = anchor.fetch_all()
    for cp in checkpoints:
        digest = canonical_digest(cp.payload())
        valid = quorum.count_valid(digest, cp.signatures)
        if valid < required:
            return AnchorVerifyResult(
                False,
                f"checkpoint @{cp.index} has {valid} valid signatures, needs {required}",
                checked=len(checkpoints),
                failed_index=cp.index,
            )
        if cp.index >= len(log.entries) or log.entries[cp.index].entry_hash != cp.head_hash:
            return AnchorVerifyResult(
                False,
                f"log does not match anchored head at index {cp.index} (truncated or rewritten)",
                checked=len(checkpoints),
                failed_index=cp.index,
            )
    return AnchorVerifyResult(True, f"all {len(checkpoints)} anchored checkpoints match", checked=len(checkpoints))
