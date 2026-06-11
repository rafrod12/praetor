"""Cryptographic primitives for Praetor.

The orchestrator is *segmented*: no single node can authorize a high-risk
action. Each signing node owns an Ed25519 keypair. A high-risk action is
approved only when at least ``threshold`` distinct nodes return a valid
signature over the canonical action digest. This is a simple, real
m-of-n threshold scheme (independent co-signatures, not key-splitting),
which is what gives Praetor its "no single compromised node" property.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


def canonical_digest(payload: dict) -> bytes:
    """Deterministic SHA-256 digest of a JSON-serialisable payload.

    Sorting keys makes the digest stable across processes and machines so
    every signer hashes exactly the same bytes.
    """
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).digest()


@dataclass
class SignerKey:
    """An Ed25519 keypair belonging to a single signing node."""

    node_id: str
    _private: Ed25519PrivateKey = field(repr=False)

    @classmethod
    def generate(cls, node_id: str) -> "SignerKey":
        return cls(node_id=node_id, _private=Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, node_id: str, seed_hex: str) -> "SignerKey":
        """Deterministic key from a 32-byte hex seed.

        Lets a containerized node keep a stable identity across restarts by
        injecting the seed as a secret instead of persisting key files.
        """
        seed = bytes.fromhex(seed_hex)
        if len(seed) != 32:
            raise ValueError("seed must be exactly 32 bytes of hex")
        return cls(node_id=node_id, _private=Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private.public_key()

    def public_key_hex(self) -> str:
        raw = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()

    def sign(self, digest: bytes) -> str:
        """Return a hex signature over ``digest``."""
        return self._private.sign(digest).hex()


def verify(public_key_hex: str, digest: bytes, signature_hex: str) -> bool:
    """Verify a single signature against a node's public key."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pub.verify(bytes.fromhex(signature_hex), digest)
        return True
    except (InvalidSignature, ValueError):
        return False


@dataclass
class ThresholdQuorum:
    """Collects and validates an m-of-n set of co-signatures.

    ``registry`` maps node_id -> public_key_hex. A quorum is reached when at
    least ``threshold`` *distinct, registered* nodes provide a valid signature
    over the same digest.
    """

    threshold: int
    registry: Dict[str, str]

    def n(self) -> int:
        return len(self.registry)

    def is_satisfied(self, digest: bytes, signatures: Dict[str, str]) -> bool:
        return self.count_valid(digest, signatures) >= self.threshold

    def count_valid(self, digest: bytes, signatures: Dict[str, str]) -> int:
        seen: set[str] = set()
        valid = 0
        for node_id, sig in signatures.items():
            if node_id in seen:
                continue
            pub = self.registry.get(node_id)
            if pub is None:
                continue
            if verify(pub, digest, sig):
                seen.add(node_id)
                valid += 1
        return valid

    def valid_signers(self, digest: bytes, signatures: Dict[str, str]) -> Iterable[str]:
        for node_id, sig in signatures.items():
            pub = self.registry.get(node_id)
            if pub is not None and verify(pub, digest, sig):
                yield node_id
