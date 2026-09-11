"""Bare mode (SPEC §2 mode (a), §4.3): with every value plane disabled, grounding is
null, the recommendation is role-advisory, ground_and_steer behaves exactly as a
Phase-1 send, and NO loomground module is imported (the assessors never run)."""

import sys

import pytest

from a2a_compliance import (
    ComplianceAgent, ControlParticipant, Roster, GroundingContext, ground,
)


def _loomground_modules():
    return [
        n for n in sys.modules
        if n.split(".", 1)[0].startswith("loomground_")
        or n.split(".", 1)[0] in ("loomground", "deontic", "rvnd")
    ]


@pytest.fixture(autouse=True)
def _disable_all_planes(monkeypatch):
    # Force every plane "absent" without uninstalling — the honest bare floor.
    monkeypatch.setenv("A2A_DISABLE_PLANES", "all")


def test_ground_is_null_and_advisory_when_all_planes_absent():
    ctx = GroundingContext(
        maker_id="maker-1",
        proposed_action={"bearer": "maker", "action": "delete the audit trail"},
        policy={"protocol": "policy-compiler/0.1",
                "norms": [{"operator": "F", "bearer": "maker",
                           "action": "delete the audit trail"}]},
    )
    result = ground(ctx)
    assert result.grounding is None                       # grounding null in bare mode
    assert result.any_grounded is False
    assert all(f.provenance == "advisory-absent" for f in result.findings)
    assert result.recommended_action == "no-steer"        # role advisory, no grounded hold
    assert _loomground_modules() == []                    # nothing imported


def test_ground_and_steer_matches_phase1_send(inbox):
    comp = ComplianceAgent(session_id="comp-1", role="policy-compliance",
                           inbox=inbox, roster=Roster())
    maker = ControlParticipant(session_id="maker-1", inbox=inbox,
                               compliance_actor="comp-1", state_provider=lambda inc: {})
    ctx = GroundingContext(
        maker_id="maker-1",
        proposed_action={"bearer": "maker", "action": "delete the audit trail"},
        policy={"protocol": "policy-compiler/0.1",
                "norms": [{"operator": "F", "bearer": "maker",
                           "action": "delete the audit trail"}]},
    )
    disp = comp.ground_and_steer("maker-1", ctx)
    # No grounded hold: bare mode yields the advisory no-steer, nothing on the wire.
    assert disp.grounding_result.recommended_action == "no-steer"
    assert disp.message is None
    assert maker.checkpoint() == []
    assert _loomground_modules() == []
