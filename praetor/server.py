"""FastAPI surface for the orchestrator.

This embeds N signing nodes in-process (default 5, quorum 3) so the whole
distributed reference monitor runs from a single ``uvicorn`` command for the
demo. In production each node would be its own process/host.
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

from .orchestrator import Orchestrator

NODE_COUNT = int(os.environ.get("PRAETOR_NODE_COUNT", "5"))
THRESHOLD = int(os.environ.get("PRAETOR_THRESHOLD", "3"))

app = FastAPI(title="Praetor", version="0.1.0", description="Distributed agent reference monitor")
orchestrator = Orchestrator(node_count=NODE_COUNT, threshold=THRESHOLD)


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


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "nodes": orchestrator.quorum.n(),
        "threshold": orchestrator.threshold,
        "audit_entries": len(orchestrator.audit.entries),
        "audit_head": orchestrator.audit.head_hash,
    }


@app.post("/action")
def action(req: ActionRequest) -> dict:
    decision = orchestrator.request_action(req.agent_id, req.action, req.resource, req.metadata)
    return decision.__dict__


@app.post("/capability/redeem")
def redeem(req: RedeemRequest) -> dict:
    ok = orchestrator.redeem_capability(req.token, req.agent_id, req.action, req.resource)
    if not ok:
        raise HTTPException(status_code=403, detail="invalid or expired capability")
    return {"redeemed": True}


@app.get("/audit")
def audit(limit: int = 50) -> dict:
    entries = [e.__dict__ for e in orchestrator.audit.entries[-limit:]]
    return {"count": len(orchestrator.audit.entries), "head": orchestrator.audit.head_hash, "entries": entries}


@app.get("/audit/verify")
def audit_verify() -> dict:
    result = orchestrator.audit.verify()
    return {"ok": result.ok, "broken_index": result.broken_index, "detail": result.detail}


@app.post("/audit/checkpoint")
def audit_checkpoint() -> dict:
    cp = orchestrator.audit.checkpoint()
    return {"index": cp.index, "head_hash": cp.head_hash, "timestamp": cp.timestamp}
