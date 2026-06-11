# Praetor Security Model

This document describes what Praetor defends against, what it assumes, and why
it is designed the way it is. Security buyers should read this first; so
should anyone trying to break it (please do — see [Reporting](#reporting)).

## What Praetor is

A **reference monitor** for AI agent actions, built to the three classic
criteria (Anderson, 1972):

| Criterion | How Praetor meets it |
|---|---|
| **Always invoked** | Agents act only through `PraetorClient.guarded(...)`; the SDK is the sole path from "agent wants" to "action happens". |
| **Tamper-proof** | The monitor itself is segmented: authorizing a high-risk action requires an m-of-n quorum of signer nodes with independent Ed25519 keys. Compromising the orchestrator or any single node forges nothing. |
| **Verifiable** | The data plane is small, open source, and deterministic; every decision is recorded in a hash-chained log whose head is quorum-signed and externally anchorable. |

## Threat model

### In scope — what Praetor defends against

| Threat | Defense |
|---|---|
| Prompt-injected or buggy agent attempts a harmful action | Action classified by deterministic policy; high-risk requires quorum; forbidden actions are statically denied |
| Stolen capability token | Tokens are single-use, short-TTL, and **sender-bound**: redemption requires a fresh signature by the agent's private key (DPoP-style proof of possession) |
| Compromised orchestrator process | The orchestrator holds no signing keys; it can only collect signatures. Below-threshold collusion yields no valid approval |
| Compromise of up to m−1 signer nodes | Quorum math: 3-of-5 for high risk, 4-of-5 for critical. Each node independently re-derives the risk tier from shared `risk_factors` — a lying orchestrator can't downgrade an action |
| Audit log edited after the fact | Hash chain breaks; `verify()` reports the exact entry |
| Audit log truncated and regrown by the operator | Quorum-signed checkpoints anchored externally (`anchor.py`); `verify_anchored()` detects heads that no longer match |
| Node outage / partition | Fail-closed: fewer than m signatures = denial, never default-allow |
| Replay of an authorization | Co-signed payloads carry a nonce and timestamp; capabilities are single-use |

### Out of scope — what Praetor does NOT defend against (v0.2)

- **A malicious host running the agent itself.** If the attacker owns the
  agent's process and its key, they are the agent. Praetor bounds what that
  agent can do (policy + quorum), not who runs it.
- **Compromise of ≥ m signer nodes.** Quorum security is exactly as strong as
  the independence of the nodes. Run them on separate hosts, providers, and
  credentials (see `docker-compose.yml` for the shape).
- **Network-level bypass.** Praetor assumes the deployment makes the broker
  the only route to tools/secrets (egress rules, no direct credentials in the
  agent environment). The SDK enforces the pattern; the network must enforce
  the perimeter.
- **Side channels in tool output / data exfiltration via approved reads.**
  Praetor authorizes actions; it does not inspect returned data.

### Trust assumptions

1. Signer nodes are operated independently (different hosts; ideally
   different failure and trust domains).
2. The agent's private key is kept out of the prompt/tool context (held by
   the SDK process, never serialized).
3. At least one anchor target is outside the operator's control.

## Design rationale

These are the three questions we expect (and have invited) from reviewers,
answered with the reasoning baked into the code.

### 1. Why m-of-n instead of a single hardened broker?

A single broker — however hardened — is a single point of *authorization*:
one RCE, one stolen key, one malicious insider, and every agent credential it
guards is live. The history of secrets management converged on the same
answer Praetor uses: split trust (Shamir-style unseal in Vault, threshold
signing in FROST/MPC custody, multi-party release in HSM ceremonies).

Praetor's variant is deliberately the simplest sound one: **independent
co-signatures, not key splitting**. Each node has its own keypair and its own
policy evaluation; an approval is a *set of independent opinions*, checkable
one by one. That buys:

- No single point of compromise — including us, the operator.
- Honest-node veto: any node can refuse and say why; refusals are visible.
- Graceful degradation that fails closed, never open.

The cost is latency on the quorum path — which is why the quorum path is
reserved for the actions where a wrong approval is expensive (see tiering).
For routine actions, the answer to "isn't this over-engineering?" is: routine
actions never touch it.

### 2. Where should the risk classifier live — static policy or ML?

**The blocking decision must be deterministic.** Praetor's classifier is a
static, reviewable table plus resource rules: the same request always yields
the same tier, auditable after the fact and testable before deployment. An ML
classifier in the blocking path means unexplainable denials, drift,
and adversarial manipulation of the thing that guards your money.

ML has a place — **escalation, never de-escalation**. `Policy.scorers`
accepts advisory scorers; a high score can *raise* a LOW action to HIGH (more
scrutiny), and a broken scorer is ignored (mediation must not depend on it).
A scorer can never lower a tier, approve anything, or suppress a static rule.
This mirrors how mature fraud systems deploy models: models flag, rules
decide.

Additionally, classification is **re-derived independently by every signer
node** from the shared `risk_factors` — the orchestrator cannot lie about an
action's tier to collect easier signatures.

### 3. Which actions most need co-signing?

The catalog (in `policy.py`) orders by blast radius and irreversibility,
informed by what production agents actually touch:

- **CRITICAL (m+1 of n):** privilege grants, permission changes, key/user
  creation, deploys — actions that *change who can act* — plus money movement
  at or above `critical_amount` (default $10k). Privilege escalation is rated
  above money because it compounds: a bad grant mints future bad actions.
- **HIGH (m of n):** payments/transfers below the critical line, deletes,
  external tool / MCP calls, agent-to-agent messages, secret access, writes,
  sends/posts/purchases.
- **LOW (sender-bound capability):** reads, lists, searches, lookups.
- **DENY (no quorum can approve):** disabling the audit log, unilateral root
  rotation — actions that attack the monitor itself.

Unknown action types are HIGH (fail-closed), not LOW.

## Cryptography

- **Signatures:** Ed25519 (`cryptography` library). Canonical payloads are
  JSON with sorted keys, hashed SHA-256.
- **Quorum:** m distinct, registered nodes must produce valid signatures over
  the same digest. Duplicate and unregistered signers are ignored.
- **Capabilities:** 192-bit URL-safe random tokens, single-use, short TTL,
  bound to the agent's registered public key when present.
- **Audit:** SHA-256 hash chain; checkpoints are `{index, head_hash,
  timestamp}` signed per-node and anchored via `FileAnchor`/`HttpAnchor`.

## Reporting

Found a vulnerability? Please open a GitHub security advisory
(Security → Advisories → "Report a vulnerability") rather than a public
issue. We commit to acknowledging within 72 hours. Adversarial review is
exactly what a reference monitor needs — credit given unless you prefer
otherwise.
