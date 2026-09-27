"""Cross-checks the committed Loomground family list against the compliance
team's role assignment and the packaged role manifests.

No network access: `a2a_compliance.family.FAMILY_REPOSITORIES` is a plain,
committed data module (see its docstring for the `gh` command used to
regenerate it), not fetched here. Nothing in this module imports subprocess,
requests or urllib, or calls `gh`.
"""

import json
from pathlib import Path

from a2a_compliance.family import (
    ARCHIVED_PUBLIC_REPOSITORIES,
    EXCLUDED_PUBLIC_REPOSITORIES,
    FAMILY_REPOSITORIES,
)
from a2a_compliance.team import COMPLIANCE_ROLES, role_manifests

FAMILY_JSON_PATH = Path(__file__).resolve().parent.parent / "a2a_compliance" / "family.json"


def _assignment_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for role in COMPLIANCE_ROLES:
        for repo in role.repositories:
            counts[repo] = counts.get(repo, 0) + 1
    return counts


def test_every_family_repo_is_assigned_exactly_once():
    counts = _assignment_counts()
    unassigned = [repo for repo in FAMILY_REPOSITORIES if counts.get(repo, 0) == 0]
    duplicated = [repo for repo in FAMILY_REPOSITORIES if counts.get(repo, 0) > 1]
    assert unassigned == [], f"family repos missing from COMPLIANCE_ROLES: {unassigned}"
    assert duplicated == [], f"family repos assigned to more than one role: {duplicated}"


def test_compliance_roles_names_no_repo_outside_the_family_list():
    family = set(FAMILY_REPOSITORIES)
    assigned = set(_assignment_counts())
    extra = assigned - family
    assert extra == set(), f"COMPLIANCE_ROLES names repos absent from the family list: {sorted(extra)}"


def test_family_list_has_no_duplicates_and_matches_expected_size():
    assert len(FAMILY_REPOSITORIES) == len(set(FAMILY_REPOSITORIES))
    assert len(FAMILY_REPOSITORIES) == 42


def test_family_list_excludes_dot_github():
    assert ".github" not in FAMILY_REPOSITORIES
    assert ".github" in EXCLUDED_PUBLIC_REPOSITORIES


def test_family_list_contains_no_archived_repo():
    archived = set(ARCHIVED_PUBLIC_REPOSITORIES)
    assert archived, "expected at least one recorded archived repo to guard against"
    overlap = archived & set(FAMILY_REPOSITORIES)
    assert overlap == set(), f"archived repos must not appear in the family list: {sorted(overlap)}"


def test_loomground_composition_is_archived_and_not_assigned():
    # loomground-composition was archived 2026-09-16 and must not be a family
    # member or own a role. This pins the correction so a future edit that
    # silently re-adds it (to the family list or to a role) is caught here.
    assert "loomground-composition" not in FAMILY_REPOSITORIES
    assert "loomground-composition" in ARCHIVED_PUBLIC_REPOSITORIES
    counts = _assignment_counts()
    assert counts.get("loomground-composition", 0) == 0, (
        "loomground-composition is archived and must not be assigned to any role"
    )


def test_family_py_and_family_json_agree():
    data = json.loads(FAMILY_JSON_PATH.read_text(encoding="utf-8"))
    assert tuple(data["family"]) == FAMILY_REPOSITORIES
    assert set(data["_excluded_public_repos"]) == set(EXCLUDED_PUBLIC_REPOSITORIES)
    assert set(data["_archived_public_repos"]) == set(ARCHIVED_PUBLIC_REPOSITORIES)


def test_team_py_and_role_json_allowed_capabilities_agree_for_family_repos():
    manifests = {manifest.id: manifest for manifest in role_manifests()}
    assert manifests.keys() == {role.id for role in COMPLIANCE_ROLES}
    for role in COMPLIANCE_ROLES:
        manifest = manifests[role.id]
        code_keys = tuple(cap.key for cap in role.capabilities)
        assert manifest.allowed_capabilities == code_keys, (
            f"role {role.id!r}: roles/{role.id}.json allowed_capabilities "
            f"{manifest.allowed_capabilities!r} does not match team.py "
            f"COMPLIANCE_ROLES capabilities {code_keys!r}"
        )
        # every repo this role owns must be reachable from at least one of its
        # own declared allowed_capabilities (kind:name), not just team.py.
        family_caps = [cap for cap in role.capabilities if cap.repo in FAMILY_REPOSITORIES]
        for cap in family_caps:
            assert cap.key in manifest.allowed_capabilities
