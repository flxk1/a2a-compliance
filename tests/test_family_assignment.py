"""Cross-checks the committed Loomground family list against the compliance
team's role assignment and the packaged role manifests.

No network access: `a2a_compliance.family.FAMILY_REPOSITORIES` is a plain,
committed data module (see its docstring for the `gh`/catalogue commands used
to regenerate it), not fetched here.
"""

from a2a_compliance.family import FAMILY_REPOSITORIES
from a2a_compliance.team import COMPLIANCE_ROLES, role_manifests


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
    assert len(FAMILY_REPOSITORIES) == 43


def test_loomground_composition_is_assigned_to_conductor():
    # The one repo this fix adds: dropped from the upstream catalogue because
    # it is deprecated/archived, but still a published family artifact (see
    # a2a_compliance/family.py docstring). Pin its placement explicitly so a
    # future edit that silently moves or drops it is caught here too.
    conductor = next(role for role in COMPLIANCE_ROLES if role.id == "conductor")
    assert "loomground-composition" in conductor.repositories


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
