"""Tests for the Praetor reference-monitor MVP."""

from praetor import Orchestrator, Policy, SignerNode
from praetor.crypto import ThresholdQuorum, canonical_digest
from praetor.policy import RiskTier
from praetor.sdk import PraetorClient, PraetorDenied


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
