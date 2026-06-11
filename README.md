# Praetor

**A distributed, agent-aware reference monitor.**
_Every agent action, co-signed and accounted for._

[![CI](https://github.com/rafrod12/praetor/actions/workflows/ci.yml/badge.svg)](https://github.com/rafrod12/praetor/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-d4a843.svg)](LICENSE)
[![Website](https://img.shields.io/badge/site-praetor-0b0e14)](https://rafrod12.github.io/praetor/)

Praetor is a non-bypassable broker that sits between your AI agents and the
actions they want to take. LLM firewalls inspect what goes *into* the model;
Praetor governs what comes *out* — the actions. High-risk actions (payments,
deletes, tool calls, secret access) require an **m-of-n quorum of independent
signing nodes**, and every decision lands in a tamper-evident audit log.

**Website / pitch:** https://rafrod12.github.io/praetor/ ·
**Design-partner program:** [apply here](https://github.com/rafrod12/praetor/issues/new?template=design-partner.yml) (5 seats)

It enforces four security pillars:

| Pillar | What it means | Where it lives |
| --- | --- | --- |
| **Complete mediation** | Every consequential action goes through the broker; the agent SDK only acts via `guarded(...)`. | [`praetor/sdk.py`](praetor/sdk.py), [`praetor/orchestrator.py`](praetor/orchestrator.py) |
| **Threshold co-signing** | High-risk actions need an **m-of-n** quorum of independent signing nodes (default **3-of-5**; critical actions escalate to **4-of-5**). No single compromised node can approve. | [`praetor/crypto.py`](praetor/crypto.py), [`praetor/signer.py`](praetor/signer.py) |
| **Tiered consensus** | Routine reads use fast, single-use, **sender-bound capability tokens** (proof-of-possession, DPoP-style); only risky actions pay the quorum cost. | [`praetor/policy.py`](praetor/policy.py) |
| **Tamper-evident audit** | Every decision is appended to a hash-chained log; any edit is detected by `verify()`, and quorum-signed checkpoints can be **anchored externally** so even the operator can't truncate history. | [`praetor/audit.py`](praetor/audit.py), [`praetor/anchor.py`](praetor/anchor.py) |

Threat model and design rationale: [SECURITY.md](SECURITY.md)

## Quick start

```powershell
# install deps
./run.ps1 install      # or: python -m pip install -r requirements.txt

# run the end-to-end story
./run.ps1 demo         # or: python demo.py

# run the test suite
./run.ps1 test         # or: python -m pytest -q

# run the HTTP orchestrator
./run.ps1 serve        # or: python -m uvicorn praetor.server:app --port 8088
```

### Docker

```bash
docker pull ghcr.io/rafrod12/praetor:edge
docker run -p 8088:8088 ghcr.io/rafrod12/praetor:edge
```

### Separated signer nodes (docker compose)

```bash
docker compose up --build
```

This runs the orchestrator plus **five signer containers, each holding its own
Ed25519 key**. Approving a high-risk action requires 3 of the 5 containers to
independently agree (4 of 5 for critical actions); the orchestrator can only
collect signatures, never produce them. Checkpoints anchor to a JSONL volume.

### pip

```bash
pip install praetor-security   # core SDK
pip install "praetor-security[server]"   # + FastAPI orchestrator server
```

## The demo, in five beats

1. **Routine read** → low-risk → sender-bound capability token issued, action runs.
2. **$250k wire payment** → amount ≥ $10k escalates to **CRITICAL** → **4-of-5** co-sign required → approved with signatures on record.
3. **Disable the audit log** → statically forbidden → denied and logged. No quorum can approve it.
4. **Degraded cluster (2 nodes)** → quorum can't be met → **fail-closed**, payment denied.
5. **Tamper attempt** → an attacker edits a past log entry → `verify()` **detects** the break.

## How an agent integrates

```python
from praetor import Orchestrator, PraetorClient

orch = Orchestrator(node_count=5, threshold=3)
agent = PraetorClient(agent_id="agent-alpha", orchestrator=orch)

# One line at the action boundary. Praetor authorizes, then your code runs.
agent.guarded("payment", "bank://acct/990 -> vendor/acme",
              perform=lambda: release_funds(),
              metadata={"amount": 250000, "currency": "USD"})
```

If Praetor denies the action, `guarded(...)` raises `PraetorDenied` and your
callable never runs.

## HTTP API (via `./run.ps1 serve`)

| Method | Path | Purpose |
| --- | --- | --- |
| GET  | `/health` | node count, threshold, remote/anchoring status, audit head |
| POST | `/agent/register` | register an agent's public key (binds its tokens) |
| POST | `/action` | mediate an action (`agent_id`, `action`, `resource`, `metadata`) |
| POST | `/capability/redeem` | redeem a single-use token (`proof` = possession signature) |
| GET  | `/audit` | recent audit entries + head hash |
| GET  | `/audit/verify` | recompute the chain (+ anchored checkpoints if configured) |
| POST | `/audit/checkpoint` | quorum-sign the head and anchor it externally |

## Layout

```
praetor/
  crypto.py        Ed25519 keys (seedable) + m-of-n threshold verification
  policy.py        risk tiers (low / high / critical / deny), advisory scorers,
                   fail-closed on unknown
  audit.py         hash-chained tamper-evident log + checkpoints
  anchor.py        quorum-signed checkpoints published externally;
                   catches operator truncation
  signer.py        a single independent signing node
  node_server.py   standalone FastAPI service for one signer (per host)
  remote.py        orchestrator-side client for remote signers (fail-closed)
  orchestrator.py  the broker: mediate, tier, co-sign, bind tokens, log, anchor
  sdk.py           PraetorClient.guarded(...) + AgentIdentity (proof of possession)
  server.py        FastAPI surface (embedded nodes, or PRAETOR_NODE_URLS)
demo.py            end-to-end story
docker-compose.yml orchestrator + 5 physically separated signer containers
tests/             pytest suite (25 tests)
SECURITY.md        threat model, trust assumptions, design rationale
```

## Scope (v0.2)

What's real today: m-of-n Ed25519 co-signing with per-tier escalation,
sender-bound (proof-of-possession) capability tokens, hash-chained audit with
quorum-signed external anchoring, and signer nodes that run as **separate
containers/hosts** via docker compose. Each node independently re-derives an
action's risk tier — a compromised orchestrator can't downgrade an action to
collect easier signatures, and it holds no signing keys at all.

What's still ahead (see [SECURITY.md](SECURITY.md) for the full model):
mTLS between orchestrator and nodes, anchoring to a public transparency
service out of the box, and an MCP proxy so any MCP-speaking agent can be
mediated with zero code changes.
