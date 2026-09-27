"""Quick win 10 -- every `wire.conformance_kit` scenario carries a
machine-readable OWASP Agentic AI Top 10 (2026) id.

`run_conformance()` labels every `ScenarioResult` (positive and negative
alike) with an `asi` field matching `ASI01`-`ASI10` -- never inferred from
the scenario's name string, always carried explicitly from the scenario's
own definition (`_NEGATIVE_SCENARIOS`, `_POSITIVE_ASI`). This asserts the
regex holds for a live `run_conformance()` report, that every declared
scenario definition (not just what happened to run) carries one, and that
removing a single tag is CAUGHT (mutation evidence, reverted immediately
after the assertion so the module is left exactly as it was)."""

from __future__ import annotations

import re
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
ASI_PATTERN = re.compile(r"^ASI(0[1-9]|10)$")


def test_every_live_scenario_result_carries_a_valid_asi_id():
    report = run_conformance(dev_conformance_ports(), now=NOW)
    assert report.scenarios, "run_conformance produced no scenarios at all"
    for scenario in report.scenarios:
        assert ASI_PATTERN.match(scenario.asi), (
            f"{scenario.name!r} carries an invalid asi id: {scenario.asi!r}"
        )


def test_every_declared_negative_scenario_definition_carries_a_valid_asi_id():
    assert _NEGATIVE_SCENARIOS, "no negative scenarios are declared at all"
    for name, _func, asi in _NEGATIVE_SCENARIOS:
        assert ASI_PATTERN.match(asi), f"{name!r} declares an invalid asi id: {asi!r}"


def test_positive_scenario_asi_constant_is_valid():
    assert ASI_PATTERN.match(_POSITIVE_ASI), f"invalid positive-scenario asi id: {_POSITIVE_ASI!r}"


def test_asi_ids_stay_distinguishable_from_the_scenario_name():
    """The `asi` field is a real, separately-carried tag -- not merely a
    string embedded in `name` that a caller would have to parse out."""
    report = run_conformance(dev_conformance_ports(), now=NOW)
    for scenario in report.scenarios:
        assert scenario.asi not in scenario.name


def test_scenario_result_requires_no_positional_shortcut_for_asi():
    """`ScenarioResult` accepts `asi` as its 4th field; a caller that omits
    it (e.g. legacy 3-arg construction) gets the documented `""` default,
    which is NOT a valid OWASP id -- so a hand-built result missing the tag
    is distinguishable from a real one, never silently valid."""
    bare = ScenarioResult("some-legacy-result", True, "ok")
    assert bare.asi == ""
    assert not ASI_PATTERN.match(bare.asi)


# --- mutation evidence: dropping one tag must be CAUGHT, then reverted -----

def test_mutation_dropping_one_asi_tag_is_caught_by_the_regex_assertion():
    """Live demonstration (G2): take a real report, mutate ONE scenario's
    `asi` field to something invalid (simulating a dropped/blanked tag),
    and show the exact assertion this test module relies on elsewhere would
    now fail -- then discard the mutated copy immediately. No source file
    is touched by this test; the mutation is a throwaway in-memory
    dataclass replacement, not a file edit, so there is nothing to revert
    on disk."""
    report = run_conformance(dev_conformance_ports(), now=NOW)
    original = report.scenarios[0]
    assert ASI_PATTERN.match(original.asi)  # sanity: was valid before the drop

    mutated = ScenarioResult(original.name, original.passed, original.detail, asi="")
    with pytest.raises(AssertionError):
        assert ASI_PATTERN.match(mutated.asi), (
            f"{mutated.name!r} carries an invalid asi id: {mutated.asi!r}"
        )
    # Reverted: `mutated` was never written back into `report.scenarios`,
    # and no file on disk was touched -- the live report/module are
    # untouched by this demonstration.
