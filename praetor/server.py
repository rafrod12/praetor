"""FastAPI surface for the orchestrator.

By default this embeds N signing nodes in-process (5, quorum 3) so the whole
distributed reference monitor runs from a single ``uvicorn`` command for the
demo. Point ``PRAETOR_NODE_URLS`` at standalone node services (see
``praetor.node_server`` and ``docker-compose.yml``) to run with physically
separated signers instead.

Environment:
  PRAETOR_NODE_COUNT   embedded node count (default 5; ignored with NODE_URLS)
  PRAETOR_THRESHOLD    base quorum threshold (default 3)
  PRAETOR_NODE_URLS    comma-separated signer URLs -> remote, separated nodes
  PRAETOR_ANCHOR_PATH  JSONL file to anchor signed checkpoints to
  PRAETOR_ANCHOR_EVERY auto-anchor every N audit entries (default 20)
"""

from __future__ import annotations

import os
from typing import Optional

try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel
except ImportError as exc:  # pragma: no cover - only needed for the HTTP server
    raise SystemExit(
        "FastAPI is required for the server. Install with: pip install -r requirements.txt"
    ) from exc

from .anchor import FileAnchor, verify_anchored
from .orchestrator import Orchestrator

NODE_COUNT = int(os.environ.get("PRAETOR_NODE_COUNT", "5"))
THRESHOLD = int(os.environ.get("PRAETOR_THRESHOLD", "3"))
NODE_URLS = [u.strip() for u in os.environ.get("PRAETOR_NODE_URLS", "").split(",") if u.strip()]
ANCHOR_PATH = os.environ.get("PRAETOR_ANCHOR_PATH", "")
ANCHOR_EVERY = int(os.environ.get("PRAETOR_ANCHOR_EVERY", "20"))


def _build_orchestrator() -> Orchestrator:
    anchor = FileAnchor(ANCHOR_PATH) if ANCHOR_PATH else None
    if NODE_URLS:
        from .remote import RemoteSignerNode

        nodes = [RemoteSignerNode(url) for url in NODE_URLS]
        return Orchestrator(nodes=nodes, threshold=THRESHOLD,
                            anchor=anchor, anchor_every=ANCHOR_EVERY if anchor else 0)
    return Orchestrator(node_count=NODE_COUNT, threshold=THRESHOLD,
                        anchor=anchor, anchor_every=ANCHOR_EVERY if anchor else 0)


app = FastAPI(title="Praetor", version="0.2.0", description="Distributed agent reference monitor")
orchestrator = _build_orchestrator()


class ActionRequest(BaseModel):
    agent_id: str
    action: str
    resource: str = ""
    metadata: Optional[dict] = None


class RedeemRequest(BaseModel):
    token: str
    agent_id: str
    action: str
    resource: str = ""
    proof: Optional[str] = None  # hex signature over the redemption payload


class RegisterRequest(BaseModel):
    agent_id: str
    public_key_hex: str


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "nodes": orchestrator.quorum.n(),
        "threshold": orchestrator.threshold,
        "remote_nodes": bool(NODE_URLS),
        "anchoring": bool(ANCHOR_PATH),
        "audit_entries": len(orchestrator.audit.entries),
        "audit_head": orchestrator.audit.head_hash,
    }


@app.post("/agent/register")
def register_agent(req: RegisterRequest) -> dict:
    orchestrator.register_agent(req.agent_id, req.public_key_hex)
    return {"registered": req.agent_id}


@app.post("/action")
def action(req: ActionRequest) -> dict:
    decision = orchestrator.request_action(req.agent_id, req.action, req.resource, req.metadata)
    return decision.__dict__


@app.post("/capability/redeem")
def redeem(req: RedeemRequest) -> dict:
    ok = orchestrator.redeem_capability(req.token, req.agent_id, req.action, req.resource, proof=req.proof)
    if not ok:
        raise HTTPException(status_code=403, detail="invalid, expired, or unproven capability")
    return {"redeemed": True}


@app.get("/audit")
def audit(limit: int = 50) -> dict:
    entries = [e.__dict__ for e in orchestrator.audit.entries[-limit:]]
    return {"count": len(orchestrator.audit.entries), "head": orchestrator.audit.head_hash, "entries": entries}


@app.get("/audit/verify")
def audit_verify() -> dict:
    result = orchestrator.audit.verify()
    out = {"ok": result.ok, "broken_index": result.broken_index, "detail": result.detail}
    if orchestrator.anchor is not None:
        anchored = verify_anchored(orchestrator.audit, orchestrator.anchor, orchestrator.quorum)
        out["anchored"] = {"ok": anchored.ok, "detail": anchored.detail, "checked": anchored.checked}
    return out


@app.post("/audit/checkpoint")
def audit_checkpoint() -> dict:
    if orchestrator.anchor is not None:
        cp = orchestrator.checkpoint_and_anchor()
        return {"index": cp.index, "head_hash": cp.head_hash,
                "timestamp": cp.timestamp, "signatures": len(cp.signatures), "anchored": True}
    cp = orchestrator.audit.checkpoint()
    return {"index": cp.index, "head_hash": cp.head_hash, "timestamp": cp.timestamp, "anchored": False}
