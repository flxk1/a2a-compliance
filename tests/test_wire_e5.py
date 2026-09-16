"""E5 conformance suite: the portable conformance kit and enforcement-grade
profile contract (`a2a_compliance.wire.conformance_kit`).

Exit criterion under test throughout (plan: 'E5 exit', portable half): the
same end-to-end vectors -- positive full run, and every negative vector
(prohibited/reserved/ready-alone/non-admitted-permit admission guarantees,
bypass/reuse/drift/argument-mutation mediation guarantees, mismatched-effect
and fabricated-discharge certification-honesty guarantees) -- run through
`run_conformance` over injected ports and are each OBSERVED to fail closed;
a deployment's claimed enforcement grade is checked against what was
actually observed, never taken on faith.

The grade-contract tests specifically hold the line that `bypass_rejected`
(clause b, "bypass is tested and rejected") is NEVER by itself enough for a
`mediated` claim -- clause (a), "no alternate path to the governed tool",
is a host structural fact this kit cannot observe and must be an explicit
`no_alternate_path_attested` attestation, checked AFTER (never instead of)
the re-derived scenario evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from a2a_compliance.wire.certification import certify
from a2a_compliance.wire.conformance_kit import (
    GRADES,
    ConformancePorts,
    ConformanceReport,
    GradeClaimRejected,
    InMemoryConformanceExecutor,
    Profile,
    ScenarioResult,
    dev_conformance_ports,
    run_conformance,
)
from a2a_compliance.wire.executor import ExecutionOutcome
from a2a_compliance.wire.verification import verify

NOW = datetime(2026, 9, 16, tzinfo=timezone.utc)


# --- the positive scenario + full negative vector list, all observed -------

def test_run_conformance_positive_and_every_negative_vector_pass():
    report = run_conformance(dev_conformance_ports(), now=NOW)
    failures = report.failures()
    assert not failures, [(f.name, f.detail) for f in failures]
    assert report.ok is True
    assert report.bypass_rejected is True
    assert report.certificate is not None

    names = {s.name for s in report.scenarios}
    assert names == {
        "positive_full_run_certifies",
        "prohibited_action_never_admits",
        "reserved_without_approval_never_admits",
        "ready_alone_never_admits",
        "non_admitted_permit_never_issued",
        "bypass_missing_permit_rejected",
        "bypass_tampered_permit_rejected",
        "reuse_nonce_replay_rejected",
        "drift_expired_permit_rejected",
        "drift_revoked_run_rejected",
        "argument_mutation_rejected",
        "mismatched_observed_effects_not_certified",
        "fabricated_discharge_not_certified",
    }


def test_positive_certificate_independently_verifies():
    ports = dev_conformance_ports()
    report = run_conformance(ports, now=NOW)
    assert report.certificate is not None
    result = verify(
        report.certificate, "OversightCertificate",
        trust_store=ports.trust_store, revocation_store=ports.revocation_store, now=NOW,
    )
    assert result.ok, result.errors


def test_each_negative_scenario_is_individually_observed_to_fail_closed():
    report = run_conformance(dev_conformance_ports(), now=NOW)
    by_name = {s.name: s for s in report.scenarios}
    for name in (
        "prohibited_action_never_admits",
        "reserved_without_approval_never_admits",
        "ready_alone_never_admits",
        "non_admitted_permit_never_issued",
        "bypass_missing_permit_rejected",
        "bypass_tampered_permit_rejected",
        "reuse_nonce_replay_rejected",
        "drift_expired_permit_rejected",
        "drift_revoked_run_rejected",
        "argument_mutation_rejected",
        "mismatched_observed_effects_not_certified",
        "fabricated_discharge_not_certified",
    ):
        assert by_name[name].passed, (name, by_name[name].detail)


def test_run_conformance_is_repeatable_against_the_same_durable_ports():
    # A host running this in CI must be able to call it more than once
    # against the same stores without a false nonce/revocation collision.
    ports = dev_conformance_ports()
    first = run_conformance(ports, now=NOW)
    second = run_conformance(ports, now=NOW)
    assert first.ok and second.ok


def test_a_scenario_that_raises_is_reported_as_a_failed_vector_not_a_crash():
    ports = dev_conformance_ports()

    class _Explosive:
        def execute(self, tool, arguments):
            raise RuntimeError("host executor blew up")

    broken = ConformancePorts(
        trust_store=ports.trust_store, revocation_store=ports.revocation_store,
        nonce_store=ports.nonce_store, executor=_Explosive(),
        approver_authority=ports.approver_authority, freshness=ports.freshness,
        stage_signer=ports.stage_signer, approval_signer=ports.approval_signer,
        permit_issuer=ports.permit_issuer, tool_recorder=ports.tool_recorder,
        reconciler=ports.reconciler, discharger=ports.discharger, certifier=ports.certifier,
    )
    report = run_conformance(broken, now=NOW)  # must not raise
    assert report.ok is False
    positive = next(s for s in report.scenarios if s.name == "positive_full_run_certifies")
    assert positive.passed is False
    assert "raised" in positive.detail


# --- a host may inject its own ExecutorPort --------------------------------

def test_host_injected_executor_is_used_instead_of_the_default():
    class _HostExecutor:
        def __init__(self) -> None:
            self.calls = 0

        def execute(self, tool, arguments):
            self.calls += 1
            return ExecutionOutcome(
                effect={"host": "custom", "tool": tool},
                executor_id="executor:host-owned", executor_role="tool-executor",
            )

    host_executor = _HostExecutor()
    ports = dev_conformance_ports(executor=host_executor)
    assert ports.executor is host_executor
    report = run_conformance(ports, now=NOW)
    assert report.ok, report.failures()
    # positive dispatch + reconciliation/discharge scenarios all execute once
    # each through the real, host-supplied executor.
    assert host_executor.calls >= 1


def test_default_executor_performs_no_host_effect():
    executor = InMemoryConformanceExecutor()
    outcome = executor.execute("anything", {"x": 1})
    assert outcome.effect == {"tool": "anything", "arguments": {"x": 1}, "ok": True}


# --- the enforcement-grade profile contract: truthful and fail-closed ------
#
# plan's `mediated` has two clauses: (a) no alternate path to the governed
# tool, (b) bypass tested and rejected. run_conformance can only ever OBSERVE
# (b) -- clause (a) is a host structural fact this in-process kit cannot
# see, so it must be an explicit attestation, never assumed on bypass_rejected
# alone. `platform` needs (a) + (b) + the host's own boundary attestation.

def test_bypass_rejected_alone_without_attestation_stays_advisory():
    # The mediation vectors genuinely passed (clause b), but the host has
    # NOT attested no-alternate-path (clause a) -- mediated is unearned.
    report = run_conformance(dev_conformance_ports(), now=NOW)
    assert report.bypass_rejected is True
    profile = Profile(claimed_grade="mediated", report=report)
    assert profile.observed_grade == "advisory"
    assert profile.verified is False
    assert profile.reported_grade() == "advisory"
    with pytest.raises(GradeClaimRejected):
        profile.assert_claim()


def test_bypass_rejected_and_no_alternate_path_attested_reports_mediated():
    report = run_conformance(dev_conformance_ports(), now=NOW)
    profile = Profile(claimed_grade="mediated", report=report, no_alternate_path_attested=True)
    assert profile.observed_grade == "mediated"
    assert profile.verified is True
    assert profile.reported_grade() == "mediated"
    profile.assert_claim()  # does not raise


def test_no_alternate_path_attestation_without_bypass_rejected_stays_advisory():
    # Attestation of clause (a) never substitutes for an actual, observed
    # rejection of clause (b) -- an attestation never overrides a bypass
    # failure (or an untested bypass, which counts the same as a failure).
    bypassable_report = ConformanceReport(
        scenarios=(
            ScenarioResult("positive_full_run_certifies", True, "ok"),
            ScenarioResult("bypass_missing_permit_rejected", False, "effect happened without a permit"),
        ),
        bypass_rejected=False,
    )
    profile = Profile(claimed_grade="mediated", report=bypassable_report, no_alternate_path_attested=True)
    assert profile.observed_grade == "advisory"
    assert profile.verified is False
    assert profile.reported_grade() == "advisory"  # downgraded, never blessed as mediated
    with pytest.raises(GradeClaimRejected):
        profile.assert_claim()


def test_advisory_claim_is_always_honoured_regardless_of_observed_strength():
    report = run_conformance(dev_conformance_ports(), now=NOW)
    profile = Profile(claimed_grade="advisory", report=report)
    assert profile.verified is True
    assert profile.reported_grade() == "advisory"


def test_untested_bypass_is_treated_the_same_as_a_failed_bypass_check():
    # "a deployment where bypass succeeds (OR IS UNTESTED) can only be
    # advisory" (contract) -- an empty/absent bypass observation must not
    # default to a passing grade, even fully attested.
    untested_report = ConformanceReport(scenarios=(), bypass_rejected=False)
    profile = Profile(
        claimed_grade="platform", report=untested_report,
        no_alternate_path_attested=True, platform_boundary_attested=True,
    )
    assert profile.reported_grade() == "advisory"
    with pytest.raises(GradeClaimRejected):
        profile.assert_claim()


def test_hand_set_bypass_rejected_flag_with_zero_scenarios_cannot_earn_mediated():
    # Robustness: the grade is derived from report.scenarios at evaluation
    # time, never trusted off a bare, possibly-tampered bypass_rejected
    # flag -- a hand-built report claiming bypass_rejected=True with NO
    # scenarios to back it must not earn a passing grade either. Only the
    # honest run_conformance() path (real scenarios, really passed) counts.
    fabricated_report = ConformanceReport(scenarios=(), bypass_rejected=True)
    profile = Profile(claimed_grade="mediated", report=fabricated_report, no_alternate_path_attested=True)
    assert profile.observed_grade == "advisory"
    assert profile.verified is False
    assert profile.reported_grade() == "advisory"
    with pytest.raises(GradeClaimRejected):
        profile.assert_claim()


def test_platform_claim_requires_both_attestations_on_top_of_the_mediation_vectors():
    report = run_conformance(dev_conformance_ports(), now=NOW)

    no_attestations = Profile(claimed_grade="platform", report=report)
    assert no_attestations.observed_grade == "advisory"  # neither attestation supplied
    assert no_attestations.verified is False
    assert no_attestations.reported_grade() == "advisory"

    only_platform_boundary = Profile(claimed_grade="platform", report=report, platform_boundary_attested=True)
    assert only_platform_boundary.observed_grade == "advisory"  # no-alternate-path still missing
    assert only_platform_boundary.verified is False

    only_no_alternate_path = Profile(claimed_grade="platform", report=report, no_alternate_path_attested=True)
    assert only_no_alternate_path.observed_grade == "mediated"  # platform boundary still missing
    assert only_no_alternate_path.verified is False
    assert only_no_alternate_path.reported_grade() == "mediated"

    both_attested = Profile(
        claimed_grade="platform", report=report,
        no_alternate_path_attested=True, platform_boundary_attested=True,
    )
    assert both_attested.observed_grade == "platform"
    assert both_attested.verified is True
    assert both_attested.reported_grade() == "platform"


def test_platform_boundary_attestation_never_overrides_an_actual_bypass_failure():
    bypassable_report = ConformanceReport(scenarios=(), bypass_rejected=False)
    profile = Profile(
        claimed_grade="platform", report=bypassable_report,
        no_alternate_path_attested=True, platform_boundary_attested=True,
    )
    assert profile.observed_grade == "advisory"  # attestations alone change nothing
    assert profile.verified is False
    assert profile.reported_grade() == "advisory"


def test_unknown_claimed_grade_is_rejected():
    report = run_conformance(dev_conformance_ports(), now=NOW)
    with pytest.raises(ValueError):
        Profile(claimed_grade="omniscient", report=report)


def test_grades_are_ordered_advisory_below_mediated_below_platform():
    assert GRADES == ("advisory", "mediated", "platform")


# --- bare-install / lazy-reachability --------------------------------------

def test_e5_symbols_are_reachable_only_via_lazy_wire_getattr():
    from a2a_compliance import wire

    assert wire.run_conformance is run_conformance
    assert wire.dev_conformance_ports is dev_conformance_ports
    assert wire.Profile is Profile
    assert wire.GradeClaimRejected is GradeClaimRejected
    assert wire.ConformancePorts is ConformancePorts
    assert wire.ConformanceReport is ConformanceReport
    assert wire.ScenarioResult is ScenarioResult
    assert wire.InMemoryConformanceExecutor is InMemoryConformanceExecutor
    assert wire.GRADES is GRADES


def test_certify_still_importable_directly_unaffected_by_conformance_kit():
    # Sanity: adding conformance_kit must not disturb existing E4 imports.
    assert certify is not None
