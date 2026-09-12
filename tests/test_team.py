from a2a_compliance import (
    ACTION_NO_STEER,
    CapabilityInventory,
    ComplianceTeam,
    ControlRequest,
    GovernanceBlock,
    GroundingContext,
    GroundingResult,
    LOOMGROUND_REPOSITORIES,
    TEAM_ROLES,
    TeamProfile,
)


def _request(*, profile=TeamProfile.LOOMGROUND, target="edit"):
    return ControlRequest(
        context=GroundingContext(maker_id="maker-1"),
        target_kind=target,
        governance=GovernanceBlock.from_dict({
            "actions": [{"kind": "edit"}],
            "reserved": [{"kind": "commit", "by": "workspace_owner"}],
            "prohibited": ["push"],
            "obligations": ["record_effects"],
        }),
        profile=profile,
    )


def _complete_inventory():
    tools, skills, contracts, distributions = set(), set(), set(), set()
    for role in TEAM_ROLES:
        for cap in role.capabilities:
            {"tool": tools, "skill": skills, "contract": contracts,
             "distribution": distributions}[cap.kind.value].add(cap.name)
    return CapabilityInventory.from_iterables(
        tools=tools, skills=skills, contracts=contracts, distributions=distributions,
    )


def _satisfied():
    return GroundingResult([], None, ACTION_NO_STEER, "all checks satisfied")


def test_manifest_assigns_all_41_public_repositories_once():
    assigned = [repo for role in TEAM_ROLES for repo in role.repositories]
    assert len(LOOMGROUND_REPOSITORIES) == 41
    assert len(assigned) == 41
    assert len(set(assigned)) == 41


def test_full_profile_routes_human_when_required_capabilities_are_missing():
    plan = ComplianceTeam().assess(_request(), _satisfied())
    assert plan.ready is False
    assert plan.disposition == "route-human"
    assert "tool:ingest_text" in plan.missing_required
    assert "tool:solver_verify" in plan.missing_required


def test_full_profile_is_ready_only_after_grounding_and_complete_required_inventory():
    team = ComplianceTeam(_complete_inventory())
    unassessed = team.plan(_request())
    assert unassessed.ready is False
    assert unassessed.disposition == "route-human"

    assessed = team.assess(_request(), _satisfied())
    assert assessed.ready is True
    assert assessed.disposition == "no-steer"
    assert assessed.missing_required == ()
    assert assessed.obligations == ("record_effects",)


def test_prohibited_and_reserved_boundary_override_available_capabilities():
    team = ComplianceTeam(_complete_inventory())
    prohibited = team.assess(_request(target="push"), _satisfied())
    reserved = team.assess(_request(target="commit"), _satisfied())
    assert prohibited.ready is False
    assert prohibited.disposition == "refuse"
    assert reserved.ready is False
    assert reserved.disposition == "route-human"


def test_protocol_profile_keeps_dependency_free_advisory_floor():
    plan = ComplianceTeam().plan(_request(profile=TeamProfile.PROTOCOL))
    assert plan.ready is True
    assert plan.disposition == "advisory"
    assert plan.steps == ()
    assert plan.missing_required == ()


def test_missing_supporting_skills_are_visible_but_do_not_block():
    inventory = _complete_inventory()
    without_skills = CapabilityInventory(
        tools=inventory.tools,
        contracts=inventory.contracts,
        distributions=inventory.distributions,
    )
    plan = ComplianceTeam(without_skills).assess(_request(), _satisfied())
    assert plan.ready is True
    assert "skill:loomground" in plan.missing_supporting
    assert "skill:policy-compiler" in plan.missing_supporting

