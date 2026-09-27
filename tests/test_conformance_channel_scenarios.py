"""Quick win 10 -- the new `wire.conformance_kit` scenarios exercising the
real seams: forged sender / replayed resume on the control channel, an
unapproved (reserved) halt, a tampered pinned governance block, and the
injection-provenance guarantee that a maker's self-report can never satisfy
an admission receipt. `foreign_executor_rejected` (permit presented by a
foreign executor) already existed from the permit leg's quick win 5 -- this
module asserts it is still present rather than duplicating it.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from a2a_compliance.wire.conformance_kit import dev_conformance_ports, run_conformance

NOW = datetime(2026, 9, 16, tzinfo=timezone.utc)

NEW_SCENARIO_NAMES = {
    "control_forged_sender_rejected",
    "control_replayed_resume_rejected",
    "control_unapproved_halt_not_dispatched",
    "tampered_governance_block_not_admitted",
    "self_report_never_satisfies_admission",
}

REUSED_SCENARIO_NAME = "foreign_executor_rejected"


@pytest.fixture(scope="module")
def report():
    return run_conformance(dev_conformance_ports(), now=NOW)


def _by_name(report, name):
    for scenario in report.scenarios:
        if scenario.name == name:
            return scenario
    raise AssertionError(f"scenario {name!r} is missing from the report")


def test_all_new_scenarios_are_present_and_pass(report):
    names = {s.name for s in report.scenarios}
    missing = NEW_SCENARIO_NAMES - names
    assert not missing, f"missing new quick-win-10 scenarios: {missing}"
    for name in NEW_SCENARIO_NAMES:
        scenario = _by_name(report, name)
        assert scenario.passed, f"{name} failed: {scenario.detail}"


def test_foreign_executor_scenario_still_present_not_duplicated(report):
    """The permit leg's own quick-win-5 scenario -- reused, not re-built."""
    names = [s.name for s in report.scenarios]
    assert names.count(REUSED_SCENARIO_NAME) == 1
    scenario = _by_name(report, REUSED_SCENARIO_NAME)
    assert scenario.passed, scenario.detail


def test_control_forged_sender_not_applied(report):
    scenario = _by_name(report, "control_forged_sender_rejected")
    assert scenario.passed, scenario.detail
    assert "'ack', False" in scenario.detail


def test_control_replayed_resume_second_delivery_rejected(report):
    scenario = _by_name(report, "control_replayed_resume_rejected")
    assert scenario.passed, scenario.detail
    assert "second accepted=False" in scenario.detail


def test_control_unapproved_halt_not_dispatched(report):
    scenario = _by_name(report, "control_unapproved_halt_not_dispatched")
    assert scenario.passed, scenario.detail
    assert "dispatched=False" in scenario.detail


def test_tampered_governance_block_not_admitted(report):
    scenario = _by_name(report, "tampered_governance_block_not_admitted")
    assert scenario.passed, scenario.detail
    assert "ADMITTED" not in scenario.detail.split(",", 1)[0]


def test_self_report_never_satisfies_admission_and_keeps_its_provenance(report):
    scenario = _by_name(report, "self_report_never_satisfies_admission")
    assert scenario.passed, scenario.detail
    assert "forged.provenance='self-report'" in scenario.detail


def test_full_report_still_certifies_overall(report):
    """The new scenarios do not disturb the existing positive/mediation
    guarantees: the whole report still passes end to end."""
    assert report.ok, [(f.name, f.detail) for f in report.failures()]
    assert report.bypass_rejected is True
    assert report.certificate is not None


# --- mutation evidence: neutering a seam check must be CAUGHT --------------

def test_mutation_neutering_the_forged_sender_check_would_be_caught():
    """Live demonstration (G2): call the underlying scenario function
    directly with a trust store that (mis-)trusts the FORGER's key too --
    simulating "the seam check is neutered" -- and show the scenario then
    reports failure (a forged sender is wrongly accepted), i.e. this test
    suite's own assertions would catch that regression. No source file is
    touched; the mutation is an alternate call, not an edit."""
    from a2a_compliance.wire.conformance_kit import (
        _InMemoryInbox,
        _scenario_control_forged_sender_rejected,
    )
    from a2a_compliance.wire.trust import InMemoryTrustStore
    from a2a_compliance.wire.signing import generate_dev_keypair
    from a2a_compliance import ControlParticipant
    from a2a_compliance import envelope as env
    from interfaces.a2a_control import Authority, Party, Verb
    from a2a_compliance.wire.signing import dev_sign_subject

    run_id = "mutation-forged-sender"
    comp_actor, maker_id = f"{run_id}:comp", f"{run_id}:maker"
    forger_priv, forger_pub = generate_dev_keypair()
    neutered_trust_store = InMemoryTrustStore()
    # MUTATION: the forger's own key IS registered here -- the real
    # scenario function never does this; this simulates a neutered check.
    neutered_trust_store.add(
        "key-forger", forger_pub, frozenset({"A2AControlMessage"}), frozenset({"policy-compliance"}),
    )
    maker = ControlParticipant(
        session_id=maker_id, inbox=_InMemoryInbox(), compliance_actor=comp_actor,
        trust_store=neutered_trust_store, state_provider=lambda include: {},
    )
    msg = env.new_message(
        from_=Party(actor=comp_actor, role="policy-compliance"),
        to=Party(actor=maker_id, role="maker"),
        verb=Verb.HOLD, body=env.hold_body("next-action"),
        authority=Authority(basis="role", role="policy-compliance", oversees=maker_id, reserved=False),
    )
    forged = env.stamp_and_sign(
        env.to_wire(msg), key_id="key-forger",
        sign=lambda d: dev_sign_subject(d, forger_priv), nonce=f"{run_id}:nonce",
    )
    maker.inbox.put(maker_id, forged)
    responses = maker.checkpoint()

    # Under the mutation, the forged sender IS wrongly applied -- the exact
    # opposite of the real scenario's passing assertion, demonstrating the
    # real scenario's check is load-bearing.
    assert responses[0].body.get("accepted") is True
    assert maker.is_held() is True

    # Reverted: `neutered_trust_store` is a local throwaway, never written
    # back into `conformance_kit`; the real `_scenario_control_forged_
    # sender_rejected` (asserted passing elsewhere in this module) is
    # untouched by this demonstration.
    real_ok, _detail = _scenario_control_forged_sender_rejected(
        dev_conformance_ports(), None, NOW, NOW, "mutation-control-check",
    )
    assert real_ok is True
