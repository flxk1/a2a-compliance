# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""evidence-grounder's coordinate tools (versum_coords/versum_cell/nd_resolve)
and the coordinate-grounding compliance receipt (`coord_grounding.py`).
"""

import json
from pathlib import Path

import jsonschema
import pytest

from a2a_compliance import (
    CANDIDATE,
    CONFIRMED,
    Coordinate,
    GroundingReference,
    TEAM_ROLES,
    build_receipt,
    role_manifests,
    resolve_grounding_reference,
)
from a2a_compliance.coord_grounding import default_resolver, nd_available
from a2a_compliance.wire import canonical

ROOT = Path(__file__).resolve().parent.parent

REF = {"dimensions": ["causal"], "anchor": "urn:dls:sha256:abc123#11-88"}


def _evidence_grounder_manifest():
    manifests = {m.id: m for m in role_manifests()}
    return manifests["evidence-grounder"]


# --- (1) tool declaration + schema validation -------------------------------

def test_evidence_grounder_declares_the_three_coordinate_tools():
    manifest = _evidence_grounder_manifest()
    for tool in ("tool:versum_coords", "tool:versum_cell", "tool:nd_resolve"):
        assert tool in manifest.allowed_capabilities


def test_evidence_grounder_role_json_validates_against_schema():
    schema = json.loads((ROOT / "schema/compliance-role.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)
    path = ROOT / "a2a_compliance/roles/evidence-grounder.json"
    validator.validate(json.loads(path.read_text()))


def test_team_py_and_role_json_stay_in_sync_for_evidence_grounder():
    manifest = _evidence_grounder_manifest()
    role = next(r for r in TEAM_ROLES if r.id == "evidence-grounder")
    code_keys = tuple(cap.key for cap in role.capabilities)
    assert manifest.allowed_capabilities == code_keys
    for tool in ("tool:versum_coords", "tool:versum_cell", "tool:nd_resolve"):
        assert tool in code_keys


# --- (2) candidate never grounds; confirmed grounds -------------------------

def test_candidate_coordinate_never_grounds():
    coord = Coordinate(reference=REF, verification=CANDIDATE)
    assert coord.grounds is False
    ref = resolve_grounding_reference(coord)
    assert ref.status == "not-grounded"
    assert ref.canonical_reference is None
    assert ref.digest is None
    assert "unconfirmed" in ref.reason

    receipt = build_receipt("maker-1", "coord-1", coord)
    assert receipt.grounded is False
    assert receipt.grounding_reference.status == "not-grounded"


def test_confirmed_coordinate_grounds():
    coord = Coordinate(reference=REF, verification=CONFIRMED)
    assert coord.grounds is True


def test_only_confirmed_tier_grounds_no_vetted_tier_present():
    # This repo has no `vetted` verification tier; only `confirmed` grounds.
    from a2a_compliance.coord_grounding import GROUNDING_TIERS
    assert GROUNDING_TIERS == frozenset({"confirmed"})
    assert "vetted" not in GROUNDING_TIERS
    assert "candidate" not in GROUNDING_TIERS


# --- (3) confirmed + resolver -> canonical reference + digest --------------

def _fake_resolver(ref):
    return {"canonical_reference": "urn:dls:sha256:abc123#11-88", "digest": {"sha256": "deadbeef"}}


def test_confirmed_coordinate_grounds_and_carries_resolver_output():
    coord = Coordinate(reference=REF, verification=CONFIRMED)
    receipt = build_receipt("maker-1", "coord-1", coord, resolver=_fake_resolver)
    assert receipt.grounded is True
    gref = receipt.grounding_reference
    assert gref.status == "resolved"
    expected = _fake_resolver(REF)
    assert gref.canonical_reference == expected["canonical_reference"]
    assert gref.digest == expected["digest"]


def test_resolver_failure_degrades_to_unresolved_never_fabricates():
    def _raising_resolver(ref):
        raise RuntimeError("store unreachable")

    coord = Coordinate(reference=REF, verification=CONFIRMED)
    ref = resolve_grounding_reference(coord, resolver=_raising_resolver)
    assert ref.status == "unresolved"
    assert ref.digest is None
    assert "store unreachable" in ref.reason


# --- (4) 5d-nd absent -> unresolved with reason -----------------------------

def test_no_resolver_and_5d_nd_absent_yields_unresolved_with_reason():
    if nd_available():
        pytest.skip("5d-nd is installed in this environment; covered by the injected-resolver tests instead")
    coord = Coordinate(reference=REF, verification=CONFIRMED)
    ref = resolve_grounding_reference(coord)
    assert ref.status == "unresolved"
    assert ref.digest is None
    assert ref.canonical_reference is None
    assert ref.reason


def test_default_resolver_is_none_when_5d_nd_absent():
    if nd_available():
        pytest.skip("5d-nd is installed in this environment")
    assert default_resolver() is None


# --- (5) receipt determinism -------------------------------------------------

def test_receipt_determinism_same_input_identical_bytes():
    coord = Coordinate(reference=REF, verification=CONFIRMED)
    r1 = build_receipt("maker-1", "coord-1", coord, resolver=_fake_resolver)
    r2 = build_receipt("maker-1", "coord-1", coord, resolver=_fake_resolver)
    assert r1.to_dict() == r2.to_dict()
    assert canonical.canonical_bytes(r1.to_dict()) == canonical.canonical_bytes(r2.to_dict())
    assert r1.digest() == r2.digest()


def test_receipt_determinism_not_grounded_path():
    coord = Coordinate(reference=REF, verification=CANDIDATE)
    r1 = build_receipt("maker-1", "coord-1", coord)
    r2 = build_receipt("maker-1", "coord-1", coord)
    assert r1.digest() == r2.digest()


def test_receipt_to_dict_carries_no_wallclock_field():
    coord = Coordinate(reference=REF, verification=CONFIRMED)
    receipt = build_receipt("maker-1", "coord-1", coord, resolver=_fake_resolver)
    d = receipt.to_dict()
    blob = json.dumps(d)
    for banned in ("time", "date", "timestamp", "clock"):
        assert banned not in blob.lower()


def test_grounding_reference_never_fabricates_digest_when_not_grounded():
    coord = Coordinate(reference=REF, verification=CANDIDATE)
    ref = resolve_grounding_reference(coord, resolver=_fake_resolver)
    # A candidate coordinate never grounds, regardless of resolver presence --
    # the resolver must never even be consulted for an unconfirmed coordinate.
    assert ref.status == "not-grounded"
    assert ref.digest is None
