"""Client for a remote signer node.

Presents the same interface as :class:`praetor.signer.SignerNode` so the
orchestrator can mix in-process and remote nodes freely. A node that is
unreachable or errors simply does not contribute a signature -- the quorum
math then fails closed, exactly like a crashed node.
"""

from __future__ import annotations

import time

import httpx

from .signer import SignResult


class RemoteSignerNode:
    """An orchestrator-side proxy for one signer running elsewhere."""

    def __init__(self, base_url: str, timeout: float = 3.0,
                 boot_retries: int = 20, boot_wait: float = 0.5) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.node_id, self.public_key_hex = self._fetch_identity(boot_retries, boot_wait)

    def _fetch_identity(self, retries: int, wait: float) -> tuple[str, str]:
        last_error: Exception | None = None
        for _ in range(max(1, retries)):
            try:
                resp = httpx.get(f"{self.base_url}/pubkey", timeout=self.timeout)
                resp.raise_for_status()
                data = resp.json()
                return data["node_id"], data["public_key_hex"]
            except Exception as exc:  # node may still be booting
                last_error = exc
                time.sleep(wait)
        raise ConnectionError(f"could not reach signer node at {self.base_url}: {last_error}")

    def _post(self, path: str, payload: dict) -> SignResult:
        try:
            resp = httpx.post(f"{self.base_url}{path}", json={"payload": payload}, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            return SignResult(
                node_id=data["node_id"],
                signed=bool(data["signed"]),
                signature=data.get("signature"),
                reason=data.get("reason", ""),
            )
        except Exception as exc:
            # Unreachable/erroring node contributes nothing: fail-closed.
            return SignResult(self.node_id, False, None, f"{self.node_id} unreachable: {exc}")

    def co_sign(self, action_payload: dict) -> SignResult:
        return self._post("/co-sign", action_payload)

    def sign_checkpoint(self, checkpoint_payload: dict) -> SignResult:
        return self._post("/sign-checkpoint", checkpoint_payload)
