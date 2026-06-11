"""End-to-end Praetor demo -- run with: python demo.py

Tells the whole story in one script:
  1. A safe read         -> low-risk capability token path.
  2. A risky payment     -> 3-of-5 threshold co-sign, approved.
  3. A forbidden action  -> statically denied, logged.
  4. A degraded cluster  -> only 2 nodes available, quorum fails, payment denied.
  5. Tamper attempt       -> someone edits the audit log; verify() catches it.
"""

from __future__ import annotations

from praetor import Orchestrator, PraetorClient
from praetor.sdk import PraetorDenied


C = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "green": "\033[32m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
    "dim": "\033[2m",
}


def banner(title: str) -> None:
    print(f"\n{C['bold']}{C['cyan']}== {title} =={C['reset']}")


def show(decision) -> None:
    color = C["green"] if decision.approved else C["red"]
    verdict = "APPROVED" if decision.approved else "DENIED"
    signers = f"  signers={decision.signers}" if decision.signers else ""
    cap = "  (capability token issued)" if decision.capability else ""
    print(
        f"  {color}{verdict}{C['reset']} "
        f"[{decision.tier}] {decision.reason}{signers}{cap} "
        f"{C['dim']}#audit={decision.audit_index}{C['reset']}"
    )


def main() -> None:
    print(f"{C['bold']}Praetor - distributed agent reference monitor{C['reset']}")
    print(f"{C['dim']}Every agent action, co-signed and accounted for.{C['reset']}")

    orch = Orchestrator(node_count=5, threshold=3)
    agent = PraetorClient(agent_id="agent-alpha", orchestrator=orch)
    print(f"\nCluster: {orch.quorum.n()} signing nodes, quorum = {orch.threshold}-of-{orch.quorum.n()}")

    # 1. Safe read -> capability token path -------------------------------
    banner("1. Routine read (low-risk, capability token)")
    try:
        result = agent.guarded("read", "db://customers/42", perform=lambda: "record#42")
        print(f"  action ran -> {C['green']}{result}{C['reset']}")
    except PraetorDenied as e:
        print(f"  blocked: {e}")

    # 2. Risky payment -> 3-of-5 threshold co-sign ------------------------
    banner("2. Wire payment $250,000 (high-risk, threshold co-sign)")
    try:
        agent.guarded(
            "payment",
            "bank://acct/990 -> vendor/acme",
            perform=lambda: print(f"  {C['green']}>> funds released{C['reset']}"),
            metadata={"amount": 250000, "currency": "USD"},
        )
    except PraetorDenied as e:
        print(f"  blocked: {e}")
    show(_last_decision(orch))

    # 3. Forbidden action -> denied ---------------------------------------
    banner("3. Attempt to disable the audit log (forbidden)")
    d = agent.request("disable_audit", "praetor://audit")
    show(d)

    # 4. Degraded cluster -> quorum fails ---------------------------------
    banner("4. Degraded cluster: only 2 nodes online, payment retried")
    degraded = Orchestrator(nodes=orch.nodes[:2], threshold=3)
    agent2 = PraetorClient(agent_id="agent-alpha", orchestrator=degraded)
    d = agent2.request("payment", "bank://acct/990 -> vendor/acme", metadata={"amount": 250000})
    show(d)
    print(f"  {C['yellow']}fail-closed: high-risk action blocked when quorum cannot be met{C['reset']}")

    # 5. Tamper attempt ---------------------------------------------------
    banner("5. Tamper-evident audit: attacker rewrites history")
    v = orch.audit.verify()
    print(f"  before tampering: {C['green']}{v.detail}{C['reset']} (ok={v.ok})")
    # Maliciously alter a past entry's reason without fixing the hash chain.
    victim = orch.audit.entries[1]
    print(f"  {C['dim']}editing audit entry #{victim.index} in place...{C['reset']}")
    victim.reason = "TAMPERED: pretend this was auto-approved"
    v = orch.audit.verify()
    color = C["green"] if not v.ok else C["red"]
    print(
        f"  after tampering:  {color}{'DETECTED' if not v.ok else 'missed'}{C['reset']} "
        f"-> {v.detail} at entry #{v.broken_index}"
    )

    banner("Audit trail")
    for e in orch.audit.entries:
        mark = C["green"] + "OK " if e.decision == "approved" else C["red"] + "DENY"
        print(
            f"  {C['dim']}#{e.index}{C['reset']} {mark}{C['reset']} "
            f"{e.agent_id} {e.action} {e.resource} {C['dim']}[{e.tier}] {e.reason}{C['reset']}"
        )

    print(f"\n{C['bold']}{C['green']}Demo complete.{C['reset']} "
          f"No single node could authorize a payment, and the log cannot be quietly edited.\n")


def _last_decision(orch: Orchestrator):
    """Reconstruct a Decision-like view from the last audit entry for display."""
    from praetor.orchestrator import Decision

    e = orch.audit.entries[-1]
    return Decision(
        approved=(e.decision == "approved"),
        tier=e.tier,
        reason=e.reason,
        signers=e.signers,
        audit_index=e.index,
        audit_hash=e.entry_hash,
    )


if __name__ == "__main__":
    main()
