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
| **Threshold co-signing** | High-risk actions need an **m-of-n** quorum of independent signing nodes (default **3-of-5**). No single compromised node can approve. | [`praetor/crypto.py`](praetor/crypto.py), [`praetor/signer.py`](praetor/signer.py) |
| **Tiered consensus** | Routine reads use fast, single-use **capability tokens**; only risky actions pay the quorum cost. | [`praetor/policy.py`](praetor/policy.py) |
| **Tamper-evident audit** | Every decision is appended to a hash-chained log; any edit to history is detected by `verify()`. | [`praetor/audit.py`](praetor/audit.py) |

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

## The demo, in five beats

1. **Routine read** → low-risk → capability token issued, action runs.
2. **$250k wire payment** → high-risk → fanned out to 5 nodes, **3-of-5** co-sign → approved.
3. **Disable the audit log** → statically forbidden → denied and logged.
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
| GET  | `/health` | node count, threshold, audit head hash |
| POST | `/action` | mediate an action (`agent_id`, `action`, `resource`, `metadata`) |
| POST | `/capability/redeem` | redeem a single-use low-risk token |
| GET  | `/audit` | recent audit entries + head hash |
| GET  | `/audit/verify` | recompute the chain; reports any tampering |
| POST | `/audit/checkpoint` | publish a checkpoint (external-anchor point) |

## Layout

```
praetor/
  crypto.py        Ed25519 keys + m-of-n threshold verification
  policy.py        risk tiers (low / high / deny), fail-closed on unknown
  audit.py         hash-chained tamper-evident log + checkpoints
  signer.py        a single independent signing node
  orchestrator.py  the broker: mediate, tier, co-sign, log
  sdk.py           PraetorClient.guarded(...) agent integration
  server.py        FastAPI surface (5 nodes embedded in-process)
demo.py            end-to-end story
tests/             pytest suite (crypto, policy, audit, orchestrator, sdk)
```

## Scope of this MVP

This is a **single-process proof of the security model**: the five signing
nodes run in-process so the whole reference monitor starts from one command.
The design intentionally maps onto a real deployment where each node is its own
host, capability tokens are signed JWT-style blobs, and audit checkpoints are
anchored to an external transparency log. Those are the next build steps, not
gaps in the model.
