import hashlib
import json
from pathlib import Path

import jsonschema

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
    role_manifests,
)
from a2a_compliance.wire import canonical


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


def test_manifest_assigns_all_42_public_repositories_once():
    assigned = [repo for role in TEAM_ROLES for repo in role.repositories]
    assert len(LOOMGROUND_REPOSITORIES) == 42
    assert len(assigned) == 42
    assert len(set(assigned)) == 42


def test_packaged_role_contracts_match_code_manifest_exactly():
    manifests = {manifest.id: manifest for manifest in role_manifests()}
    roles = {role.id: role for role in TEAM_ROLES}
    assert len(manifests) == len(roles) == 8
    assert manifests.keys() == roles.keys()
    for role_id, role in roles.items():
        manifest = manifests[role_id]
        assert manifest.identity == f"a2a-compliance/{role_id}"
        assert manifest.purpose == role.purpose
        assert manifest.allowed_capabilities == tuple(c.key for c in role.capabilities)
        assert manifest.may_dispatch is False
        assert "host_dispatch" in manifest.prohibited_effects


def test_role_contract_files_validate_against_published_schema():
    root = Path(__file__).parent.parent
    schema = json.loads((root / "schema/compliance-role.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)
    files = sorted((root / "a2a_compliance/roles").glob("*.json"))
    assert len(files) == 8
    for path in files:
        validator.validate(json.loads(path.read_text()))


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


def _action_subject(request: ControlRequest) -> dict:
    # exact shape team.py's ComplianceTeam.plan() builds before digesting
    return {
        "maker_id": request.context.maker_id,
        "target_kind": request.target_kind,
        "proposed_action": request.context.proposed_action,
    }


def test_action_digest_routes_through_the_one_canonical_digest_implementation():
    cases = [
        _request(),
        _request(target="commit"),
        ControlRequest(
            context=GroundingContext(
                maker_id="maker-2",
                proposed_action={"bearer": "maker-2", "action": "deploy", "count": 3},
            ),
            target_kind="deploy",
            governance=GovernanceBlock.from_dict({"actions": [{"kind": "deploy"}]}),
            profile=TeamProfile.PROTOCOL,
        ),
    ]
    for request in cases:
        plan = ComplianceTeam().plan(request)
        assert plan.action_digest == canonical.digest_hex(_action_subject(request))


def test_action_digest_locks_in_canonical_on_a_number_that_diverged_under_json_dumps():
    # 1e20: JCS expands it to the fixed-point digit string "100000000000000000000";
    # the old team.py method (json.dumps(sort_keys=True)) kept "1e+20". Different
    # bytes, different sha256 -- this is the case the two implementations
    # disagreed on. Routing through canonical.digest_hex must produce the JCS
    # result, not the old json.dumps one.
    request = ControlRequest(
        context=GroundingContext(
            maker_id="maker-3",
            proposed_action={"bearer": "maker-3", "action": "transfer", "amount": 1e20},
        ),
        target_kind="transfer",
        governance=GovernanceBlock.from_dict({"actions": [{"kind": "transfer"}]}),
        profile=TeamProfile.PROTOCOL,
    )
    subject = _action_subject(request)
    plan = ComplianceTeam().plan(request)

    old_method_digest = hashlib.sha256(json.dumps(
        subject, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")).hexdigest()

    assert plan.action_digest == canonical.digest_hex(subject)
    assert plan.action_digest != old_method_digest  # proves this case would have diverged


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
