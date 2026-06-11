"""Standalone HTTP service for a single signer node.

Run one of these per host/container to physically separate the quorum:

    PRAETOR_NODE_ID=node-1 python -m uvicorn praetor.node_server:app --port 9000

Environment:
  PRAETOR_NODE_ID    required node identity (e.g. node-1)
  PRAETOR_NODE_SEED  optional 32-byte hex seed for a stable key across
                     restarts (inject as a secret); omitted = ephemeral key

The node holds its own private key and applies its own policy; the
orchestrator only ever sees public keys and signatures.
"""

from __future__ import annotations

import os

try:
    from fastapi import FastAPI
    from pydantic import BaseModel
except ImportError as exc:  # pragma: no cover - only needed for the HTTP server
    raise SystemExit(
        "FastAPI is required for the node server. Install with: pip install -r requirements.txt"
    ) from exc

from .crypto import SignerKey
from .signer import SignerNode

NODE_ID = os.environ.get("PRAETOR_NODE_ID", "node-1")
NODE_SEED = os.environ.get("PRAETOR_NODE_SEED", "")

_key = SignerKey.from_seed(NODE_ID, NODE_SEED) if NODE_SEED else None
node = SignerNode(NODE_ID, key=_key)

app = FastAPI(title=f"Praetor signer {NODE_ID}", version="0.2.0")


class CoSignRequest(BaseModel):
    payload: dict


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "node_id": node.node_id}


@app.get("/pubkey")
def pubkey() -> dict:
    return {"node_id": node.node_id, "public_key_hex": node.public_key_hex}


@app.post("/co-sign")
def co_sign(req: CoSignRequest) -> dict:
    result = node.co_sign(req.payload)
    return {
        "node_id": result.node_id,
        "signed": result.signed,
        "signature": result.signature,
        "reason": result.reason,
    }


@app.post("/sign-checkpoint")
def sign_checkpoint(req: CoSignRequest) -> dict:
    result = node.sign_checkpoint(req.payload)
    return {
        "node_id": result.node_id,
        "signed": result.signed,
        "signature": result.signature,
        "reason": result.reason,
    }
