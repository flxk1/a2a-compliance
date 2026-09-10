"""Governance-block reader — steering bound (SPEC §7)."""

from a2a_compliance import GovernanceBlock, SteerDecision


def test_from_manifest_parses_block(maker_block):
    assert maker_block.grade == "L1"
    assert maker_block.action_kinds == {"read", "edit", "run-tests"}
    assert maker_block.prohibited == {"push", "key-ops"}
    assert "commit" in maker_block.reserved
    assert maker_block.obligations == ["tests-green"]


def test_steers_within_actions(maker_block):
    r = maker_block.rule("edit")
    assert r.decision is SteerDecision.STEER
    assert maker_block.may_steer("edit") is True


def test_refuses_prohibited(maker_block):
    r = maker_block.rule("push")
    assert r.decision is SteerDecision.REFUSE
    assert "prohibited" in r.reason
    assert maker_block.may_steer("push") is False


def test_routes_reserved_to_human(maker_block):
    r = maker_block.rule("commit")
    assert r.decision is SteerDecision.ROUTE_HUMAN
    assert r.reserved_by == "workspace_owner"


def test_undeclared_kind_is_refused_as_outside_boundary(maker_block):
    r = maker_block.rule("deploy")
    assert r.decision is SteerDecision.REFUSE
    assert "outside the" in r.reason


def test_prohibited_wins_even_if_also_listed_elsewhere():
    block = GovernanceBlock.from_dict({
        "actions": [{"kind": "push", "risk": "high"}],  # contradictory declaration
        "prohibited": ["push"],
    })
    # fail-closed: prohibited dominates.
    assert block.rule("push").decision is SteerDecision.REFUSE
