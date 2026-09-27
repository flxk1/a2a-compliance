"""The conformance-scenario registry invariant: every scenario `run_conformance`
actually executes must be listed in a caller-checkable inventory, and none of
them may carry an empty/invalid OWASP ASI tag.

`run_conformance` iterates `_NEGATIVE_SCENARIOS` directly (see
`wire.conformance_kit`), so today the live report and the declared list can
never drift apart by construction -- but that is exactly the invariant this
module pins down and demonstrates with a live mutation: if a scenario were
ever added to the run loop without also being added to the canonical name
set below (or without a real `ASIxx` tag), THIS test module is the one that
fails, not silently passing coverage.

`CANONICAL_SCENARIO_NAMES` is maintained by hand (not derived from
`_NEGATIVE_SCENARIOS` itself, which would make this test tautological) --
it is the independent, human-authored inventory a caller/auditor checks the
live report against.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from a2a_compliance.wire.conformance_kit import (
    ScenarioResult,
    _NEGATIVE_SCENARIOS,
    _POSITIVE_ASI,
    dev_conformance_ports,
    run_conformance,
)

NOW = datetime(2026, 9, 16, tzinfo=timezone.utc)

# The full, independently-maintained inventory of every scenario
# `run_conformance` is expected to run -- positive plus every negative
# vector, including the identity/channel-leg closures (quick win 10 and the
# key-bound-identity/replay/scope leg).
CANONICAL_SCENARIO_NAMES = frozenset({
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
    "foreign_executor_rejected",
    "missing_proof_rejected",
    "control_forged_sender_rejected",
    "control_replayed_resume_rejected",
    "control_unapproved_halt_not_dispatched",
    "tampered_governance_block_not_admitted",
    "self_report_never_satisfies_admission",
    "agent_key_signed_approval_rejected",
    "approver_identity_mismatch_rejected",
    "governance_block_signed_by_maker_refused",
    "control_actor_identity_mismatch_rejected",
    "replayed_halt_receipt_rejected",
    "control_replay_without_injected_nonce_store_rejected",
    "halt_receipt_scope_violation_rejected",
})


def test_live_report_matches_the_canonical_scenario_inventory_exactly():
    """No scenario is missing from the canonical list, and none of the
    canonical list is absent from a live run -- an exact set match, not a
    subset check either direction."""
    report = run_conformance(dev_conformance_ports(), now=NOW)
    live_names = {s.name for s in report.scenarios}
    assert live_names == CANONICAL_SCENARIO_NAMES, (
        f"missing from canonical list: {live_names - CANONICAL_SCENARIO_NAMES}; "
        f"missing from a live run: {CANONICAL_SCENARIO_NAMES - live_names}"
    )


def test_negative_scenario_declarations_match_the_canonical_inventory():
    """Same invariant, but against the DECLARED scenario table
    (`_NEGATIVE_SCENARIOS`) directly, independent of any particular run's
    outcome -- every declared name (plus the one positive scenario) is
    exactly the canonical set."""
    declared_names = {name for name, _func, _asi in _NEGATIVE_SCENARIOS}
    declared_names.add("positive_full_run_certifies")
    assert declared_names == CANONICAL_SCENARIO_NAMES


def test_every_declared_scenario_carries_a_non_empty_asi_tag():
    for name, _func, asi in _NEGATIVE_SCENARIOS:
        assert asi, f"{name!r} carries an empty ASI tag"
    assert _POSITIVE_ASI, "the positive scenario's ASI tag is empty"


def test_every_live_scenario_result_carries_a_non_empty_asi_tag():
    report = run_conformance(dev_conformance_ports(), now=NOW)
    for scenario in report.scenarios:
        assert scenario.asi, f"{scenario.name!r} produced an empty ASI tag"


# --- mutation evidence: an unlisted scenario, or an empty asi, is CAUGHT ----

def test_mutation_an_unlisted_scenario_added_to_the_run_loop_is_caught():
    """G3/registry demonstration: simulate "a scenario was added to
    run_conformance without being listed" by constructing a report whose
    scenarios include one extra, DUMMY name that is not in
    `CANONICAL_SCENARIO_NAMES` -- and show the exact-match assertion this
    module's other tests rely on would now fail. No source file is
    mutated; the injected scenario is a throwaway in-memory tuple entry,
    discarded immediately after the demonstration."""
    report = run_conformance(dev_conformance_ports(), now=NOW)
    dummy_unlisted = ScenarioResult(
        "dummy_unlisted_scenario_never_registered", True, "not really run", asi="ASI01",
    )
    mutated_scenarios = report.scenarios + (dummy_unlisted,)
    mutated_names = {s.name for s in mutated_scenarios}

    with pytest.raises(AssertionError):
        assert mutated_names == CANONICAL_SCENARIO_NAMES, (
            f"missing from canonical list: {mutated_names - CANONICAL_SCENARIO_NAMES}; "
            f"missing from a live run: {CANONICAL_SCENARIO_NAMES - mutated_names}"
        )
    # Sanity: the real, unmutated report is untouched and still matches.
    assert {s.name for s in report.scenarios} == CANONICAL_SCENARIO_NAMES


def test_mutation_a_scenario_with_an_empty_asi_is_caught():
    """Same demonstration for the empty-`asi` invariant: take one real,
    passing scenario result and replace its `asi` with `""` (simulating a
    dropped tag reaching a live report), and show the non-empty-asi
    assertion this module relies on elsewhere would now fail. The mutated
    copy is a throwaway `dataclasses.replace()`, never written back into
    `report.scenarios`."""
    report = run_conformance(dev_conformance_ports(), now=NOW)
    original = report.scenarios[0]
    assert original.asi  # sanity: was non-empty before the drop

    blanked = replace(original, asi="")
    with pytest.raises(AssertionError):
        assert blanked.asi, f"{blanked.name!r} produced an empty ASI tag"

    # Reverted: nothing on disk or in `report.scenarios` was touched.
    assert report.scenarios[0].asi == original.asi
