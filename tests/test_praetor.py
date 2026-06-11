"""Tests for the Praetor reference-monitor MVP."""

from praetor import MemoryAnchor, Orchestrator, Policy, SignerNode, verify_anchored
from praetor.crypto import SignerKey, ThresholdQuorum, canonical_digest
from praetor.orchestrator import redemption_payload
from praetor.policy import RiskTier
from praetor.sdk import AgentIdentity, PraetorClient, PraetorDenied


# ----- crypto / threshold -------------------------------------------------

def test_threshold_quorum_requires_m_of_n():
    nodes = [SignerNode(f"node-{i}") for i in range(5)]
    quorum = ThresholdQuorum(threshold=3, registry={n.node_id: n.public_key_hex for n in nodes})
    payload = {"action": "payment", "resource": "x"}
    digest = canonical_digest(payload)

    # 2 signatures -> not enough
    sigs = {nodes[0].node_id: nodes[0].co_sign(payload).signature,
            nodes[1].node_id: nodes[1].co_sign(payload).signature}
    assert not quorum.is_satisfied(digest, sigs)

    # 3 signatures -> quorum
    sigs[nodes[2].node_id] = nodes[2].co_sign(payload).signature
    assert quorum.is_satisfied(digest, sigs)


def test_forged_signature_is_rejected():
    nodes = [SignerNode(f"node-{i}") for i in range(3)]
    quorum = ThresholdQuorum(threshold=2, registry={n.node_id: n.public_key_hex for n in nodes})
    payload = {"action": "payment", "resource": "x"}
    digest = canonical_digest(payload)
    sigs = {"node-0": nodes[0].co_sign(payload).signature, "node-1": "00" * 64}
    assert quorum.count_valid(digest, sigs) == 1


def test_unregistered_node_signature_ignored():
    nodes = [SignerNode(f"node-{i}") for i in range(2)]
    quorum = ThresholdQuorum(threshold=1, registry={nodes[0].node_id: nodes[0].public_key_hex})
    payload = {"action": "delete", "resource": "y"}
    digest = canonical_digest(payload)
    sigs = {nodes[1].node_id: nodes[1].co_sign(payload).signature}  # not in registry
    assert quorum.count_valid(digest, sigs) == 0


# ----- policy -------------------------------------------------------------

def test_policy_classification():
    p = Policy()
    assert p.classify("read", "db://x").tier is RiskTier.LOW
    assert p.classify("payment", "bank://x").tier is RiskTier.HIGH
    assert p.classify("disable_audit", "praetor://audit").tier is RiskTier.DENY
    # unknown -> fail closed (HIGH)
    assert p.classify("frobnicate", "?").tier is RiskTier.HIGH


# ----- orchestrator flow --------------------------------------------------

def test_low_risk_issues_capability():
    orch = Orchestrator(node_count=5, threshold=3)
    d = orch.request_action("agent-1", "read", "db://a")
    assert d.approved and d.tier == "low" and d.capability


def test_high_risk_reaches_quorum_and_approves():
    orch = Orchestrator(node_count=5, threshold=3)
    d = orch.request_action("agent-1", "payment", "bank://a", {"amount": 100})
    assert d.approved
    assert d.tier == "high"
    assert len(d.signers) >= 3


def test_high_risk_fails_closed_without_quorum():
    full = Orchestrator(node_count=5, threshold=3)
    degraded = Orchestrator(nodes=full.nodes[:2], threshold=3)
    d = degraded.request_action("agent-1", "payment", "bank://a", {"amount": 100})
    assert not d.approved


def test_forbidden_action_denied():
    orch = Orchestrator(node_count=5, threshold=3)
    d = orch.request_action("agent-1", "disable_audit", "praetor://audit")
    assert not d.approved and d.tier == "deny"


# ----- audit tamper-evidence ---------------------------------------------

def test_audit_chain_intact_then_detects_tampering():
    orch = Orchestrator(node_count=5, threshold=3)
    orch.request_action("agent-1", "read", "db://a")
    orch.request_action("agent-1", "payment", "bank://a", {"amount": 1})
    orch.request_action("agent-1", "delete", "db://a")

    assert orch.audit.verify().ok

    orch.audit.entries[1].reason = "tampered"
    result = orch.audit.verify()
    assert not result.ok
    assert result.broken_index == 1


# ----- SDK guard ----------------------------------------------------------

def test_sdk_guarded_blocks_denied_action():
    orch = Orchestrator(node_count=5, threshold=3)
    client = PraetorClient("agent-1", orch)
    ran = {"v": False}

    try:
        client.guarded("disable_audit", "praetor://audit", perform=lambda: ran.__setitem__("v", True))
        assert False, "should have raised"
    except PraetorDenied:
        pass
    assert ran["v"] is False


def test_sdk_guarded_runs_approved_action():
    orch = Orchestrator(node_count=5, threshold=3)
    client = PraetorClient("agent-1", orch)
    out = client.guarded("payment", "bank://a", perform=lambda: "done", metadata={"amount": 5})
    assert out == "done"


def test_capability_is_single_use():
    orch = Orchestrator(node_count=5, threshold=3)
    d = orch.request_action("agent-1", "read", "db://a")
    assert orch.redeem_capability(d.capability, "agent-1", "read", "db://a")
    # second redemption fails
    assert not orch.redeem_capability(d.capability, "agent-1", "read", "db://a")


# ----- sender-bound capabilities (proof of possession) ---------------------

def test_bound_capability_requires_proof():
    orch = Orchestrator(node_count=5, threshold=3)
    identity = AgentIdentity("agent-1")
    orch.register_agent("agent-1", identity.public_key_hex)

    d = orch.request_action("agent-1", "read", "db://a")
    # no proof -> rejected even with the right token
    assert not orch.redeem_capability(d.capability, "agent-1", "read", "db://a")

    d2 = orch.request_action("agent-1", "read", "db://a")
    proof = identity.prove(redemption_payload(d2.capability, "agent-1", "read", "db://a"))
    assert orch.redeem_capability(d2.capability, "agent-1", "read", "db://a", proof=proof)


def test_stolen_token_useless_without_agent_key():
    orch = Orchestrator(node_count=5, threshold=3)
    victim = AgentIdentity("agent-1")
    orch.register_agent("agent-1", victim.public_key_hex)
    d = orch.request_action("agent-1", "read", "db://a")

    thief = AgentIdentity("agent-1")  # same id, different key
    forged = thief.prove(redemption_payload(d.capability, "agent-1", "read", "db://a"))
    assert not orch.redeem_capability(d.capability, "agent-1", "read", "db://a", proof=forged)


def test_sdk_client_auto_registers_and_proves():
    orch = Orchestrator(node_count=5, threshold=3)
    client = PraetorClient("agent-1", orch)
    assert orch.agent_key("agent-1") == client.identity.public_key_hex
    assert client.guarded("read", "db://a", perform=lambda: "ok") == "ok"


# ----- critical tier (escalated quorum) ------------------------------------

def test_large_payment_escalates_to_critical():
    p = Policy()
    assert p.classify("payment", "bank://x", {"amount": 250_000}).tier is RiskTier.CRITICAL
    assert p.classify("payment", "bank://x", {"amount": 50}).tier is RiskTier.HIGH


def test_critical_requires_larger_quorum():
    # 3 of 5 nodes online: enough for HIGH (3), not for CRITICAL (4).
    full = Orchestrator(node_count=5, threshold=3)
    degraded = Orchestrator(nodes=full.nodes[:3], threshold=3)

    high = degraded.request_action("agent-1", "payment", "bank://a", {"amount": 50})
    assert high.approved and high.tier == "high"

    critical = degraded.request_action("agent-1", "payment", "bank://a", {"amount": 250_000})
    assert not critical.approved and critical.tier == "critical"


def test_privilege_actions_are_critical():
    p = Policy()
    assert p.classify("grant_access", "iam://admin").tier is RiskTier.CRITICAL
    assert p.classify("modify_permissions", "iam://role").tier is RiskTier.CRITICAL


# ----- advisory scorers (escalate-only) -------------------------------------

def test_scorer_escalates_low_to_high():
    hot = Policy(scorers=[lambda a, r, m: 0.95])
    cls = hot.classify("read", "db://secrets-adjacent")
    assert cls.tier is RiskTier.HIGH and "escalated" in cls.reason


def test_scorer_never_deescalates_and_broken_scorer_ignored():
    def broken(a, r, m):
        raise RuntimeError("model fell over")

    p = Policy(scorers=[broken, lambda a, r, m: 0.0])
    assert p.classify("payment", "bank://x", {"amount": 5}).tier is RiskTier.HIGH
    assert p.classify("read", "db://x").tier is RiskTier.LOW


# ----- external anchoring ---------------------------------------------------

def test_anchored_checkpoints_verify_and_catch_truncation():
    anchor = MemoryAnchor()
    orch = Orchestrator(node_count=5, threshold=3, anchor=anchor)
    orch.request_action("agent-1", "read", "db://a")
    orch.request_action("agent-1", "payment", "bank://a", {"amount": 1})
    cp = orch.checkpoint_and_anchor()
    assert cp is not None and len(cp.signatures) == 5

    ok = verify_anchored(orch.audit, anchor, orch.quorum)
    assert ok.ok

    # operator truncates the log and regrows it -> anchored head no longer matches
    orch.audit.entries = orch.audit.entries[:1]
    bad = verify_anchored(orch.audit, anchor, orch.quorum)
    assert not bad.ok and "truncated or rewritten" in bad.detail


def test_anchor_rejects_underspecified_checkpoint():
    from praetor import SignedCheckpoint

    anchor = MemoryAnchor()
    orch = Orchestrator(node_count=5, threshold=3, anchor=anchor)
    orch.request_action("agent-1", "read", "db://a")
    # forged checkpoint with no signatures
    anchor.publish(SignedCheckpoint(index=0, head_hash=orch.audit.head_hash, timestamp=0.0))
    res = verify_anchored(orch.audit, anchor, orch.quorum)
    assert not res.ok and "needs 3" in res.detail


# ----- signer hygiene --------------------------------------------------------

def test_node_refuses_to_cosign_low_risk():
    node = SignerNode("node-1")
    res = node.co_sign({"action": "read", "resource": "db://a", "risk_factors": {}})
    assert not res.signed


def test_seeded_keys_are_deterministic():
    seed = "ab" * 32
    k1 = SignerKey.from_seed("node-1", seed)
    k2 = SignerKey.from_seed("node-1", seed)
    assert k1.public_key_hex() == k2.public_key_hex()


# ----- node server (separated-host surface) ----------------------------------

def test_node_server_cosigns_over_http():
    from fastapi.testclient import TestClient

    from praetor import node_server
    from praetor.crypto import verify

    client = TestClient(node_server.app)
    pub = client.get("/pubkey").json()["public_key_hex"]

    payload = {"action": "payment", "resource": "bank://a",
               "risk_factors": {"amount": 50}, "nonce": "00", "ts": 0}
    resp = client.post("/co-sign", json={"payload": payload}).json()
    assert resp["signed"]
    assert verify(pub, canonical_digest(payload), resp["signature"])
