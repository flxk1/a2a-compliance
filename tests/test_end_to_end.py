"""Bare-mode end-to-end flow (SPEC §2 mode (a), §9): compliance issues a
directive -> maker receives it via the poll inbox -> reports state -> honours a
hold and a halt at a checkpoint. Plus out-of-role denial and the governance
boundary bounding steering."""

import pytest

from a2a_compliance import (
    Verb, ComplianceAgent, ControlParticipant, Roster, SteerDecision,
)


@pytest.fixture
def wired(inbox, maker_block):
    comp = ComplianceAgent(
        session_id="comp-1", role="policy-compliance", inbox=inbox,
        roster=Roster(), maker_blocks={"maker-1": maker_block},
    )
    state = {
        "mandate": {"purpose": "refactor module X"},
        "trajectory": [{"step": "read"}, {"step": "edit"}],
        "tools": {"Read": 3, "Edit": 2},
        "claims": [{"claim": "tests pass", "evidence": "none"}],
    }
    maker = ControlParticipant(
        session_id="maker-1", inbox=inbox, compliance_actor="comp-1",
        state_provider=lambda include: {k: state[k] for k in include if k in state},
    )
    return comp, maker


def test_query_state_then_report_state_roundtrip(wired):
    comp, maker = wired
    res = comp.query_state("maker-1", ["mandate", "trajectory"])
    assert res.dispatched

    # maker polls at its checkpoint and answers
    responses = maker.checkpoint()
    assert len(responses) == 1
    assert responses[0].verb is Verb.REPORT_STATE
    assert responses[0].body["provenance"] == "self-report"

    # compliance collects the report
    replies = comp.collect_replies()
    assert len(replies) == 1
    assert replies[0].body["mandate"]["purpose"] == "refactor module X"
    assert replies[0].body["provenance"] == "self-report"  # never promoted


def test_issue_directive_received_and_acked(wired):
    comp, maker = wired
    res = comp.issue_directive(
        "maker-1", "keep edits inside module X", "constrain", target_kind="edit",
    )
    assert res.dispatched
    assert res.ruling.decision is SteerDecision.STEER

    responses = maker.checkpoint()
    assert responses[0].verb is Verb.ACK
    assert responses[0].body["accepted"] is True
    assert len(maker.directives) == 1
    assert maker.directives[0].kind == "constrain"

    replies = comp.collect_replies()
    assert replies[0].body["directive_ref"] == res.message.id


def test_hold_then_resume_honored_at_checkpoint(wired):
    comp, maker = wired
    hold_res = comp.hold("maker-1", "session", conditions=["await review"])
    assert hold_res.dispatched
    maker.checkpoint()
    assert maker.is_held() is True

    resume_res = comp.resume("maker-1", hold_ref=hold_res.message.id)
    assert resume_res.dispatched
    maker.checkpoint()
    assert maker.is_held() is False


def test_halt_is_reserved_surfaced_then_cooperative_stop(wired):
    comp, maker = wired

    # Without human confirmation the reserved act is surfaced, NOT dispatched.
    surfaced = comp.halt("maker-1", reason_ref="off-mandate")
    assert surfaced.dispatched is False
    assert surfaced.surfaced_to_human is True
    assert maker.checkpoint() == []          # nothing delivered
    assert maker.should_continue() is True

    # With confirmation (the human approved) it dispatches; maker stops at its
    # next checkpoint — a cooperative stop, not a forced kill.
    approved = comp.halt("maker-1", reason_ref="off-mandate", confirm=True)
    assert approved.dispatched is True
    assert maker.should_continue() is True   # not stopped until it checkpoints
    responses = maker.checkpoint()
    assert responses[0].verb is Verb.ACK
    assert "not a forced kill" in responses[0].body["note"]
    assert maker.should_continue() is False  # cooperative stop now in effect


def test_full_flow_in_one_maker_loop(wired):
    """A realistic maker loop that checkpoints between steps and yields to a
    halt cooperatively."""
    comp, maker = wired
    steps_done = []

    # compliance queues a directive, then a halt (human-approved)
    comp.issue_directive("maker-1", "narrow scope", "constrain", target_kind="edit")
    comp.halt("maker-1", confirm=True)

    for step in ["read", "edit", "run-tests", "commit-attempt"]:
        maker.checkpoint()               # honour any pending control messages
        if not maker.should_continue():  # cooperative yield
            break
        if maker.is_held():
            continue
        steps_done.append(step)

    # the halt landed at the first checkpoint, so no work steps ran
    assert steps_done == []
    assert maker.should_continue() is False
    assert len(maker.directives) == 1


def test_out_of_role_directive_denied(inbox, maker_block):
    # a maker role trying to steer another maker is denied by the authority model
    rogue = ComplianceAgent(session_id="backend-x", role="backend", inbox=inbox)
    res = rogue.issue_directive("maker-1", "do X", "correct")
    assert res.dispatched is False
    assert "not a compliance role" in res.denied_reason


def test_out_of_oversight_directive_denied(inbox, maker_block):
    roster = Roster(oversight={"policy-compliance": {"maker-1"}})
    comp = ComplianceAgent(session_id="comp-1", role="policy-compliance",
                           inbox=inbox, roster=roster)
    res = comp.issue_directive("maker-2", "do X", "correct")
    assert res.dispatched is False
    assert "does not oversee" in res.denied_reason


def test_directive_into_prohibited_is_refused(wired):
    comp, maker = wired
    res = comp.issue_directive("maker-1", "force push it", "redirect", target_kind="push")
    assert res.dispatched is False
    assert res.ruling.decision is SteerDecision.REFUSE
    assert maker.checkpoint() == []  # nothing was ever delivered to the maker


def test_directive_into_reserved_routes_to_human(wired):
    comp, maker = wired
    res = comp.issue_directive("maker-1", "commit the work", "redirect", target_kind="commit")
    assert res.dispatched is False
    assert res.surfaced_to_human is True
    assert res.ruling.decision is SteerDecision.ROUTE_HUMAN
    assert maker.checkpoint() == []
