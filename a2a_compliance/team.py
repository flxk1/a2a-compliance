"""Loomground compliance-team plan: consume the family, do not reimplement it.

This module is deliberately orchestration-only.  It names the public repository,
tool, skill and contract capabilities that participate in a compliance decision,
checks that the selected profile can supply them, and returns an inert plan.  It
does not call a tool, dispatch to a maker, write evidence, or enforce an action.
Those effects belong to an injected host/orchestrator after it has honoured the
plan's gates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
from importlib.resources import files
from typing import Iterable, Optional

from .governance_block import GovernanceBlock, SteerDecision, SteerRuling
from .grounding import ACTION_ROUTE_HUMAN, GroundingContext, GroundingResult
from .wire import canonical


class TeamProfile(str, Enum):
    """The dependency-light protocol floor and the fail-closed family profile."""

    PROTOCOL = "protocol"
    LOOMGROUND = "loomground"


class CapabilityKind(str, Enum):
    TOOL = "tool"
    SKILL = "skill"
    CONTRACT = "contract"
    DISTRIBUTION = "distribution"


@dataclass(frozen=True)
class Capability:
    repo: str
    kind: CapabilityKind
    name: str
    required: bool = True

    @property
    def key(self) -> str:
        return f"{self.kind.value}:{self.name}"


@dataclass(frozen=True)
class ComplianceRole:
    id: str
    purpose: str
    capabilities: tuple[Capability, ...]

    @property
    def repositories(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(c.repo for c in self.capabilities))


@dataclass(frozen=True)
class RoleManifest:
    id: str
    identity: str
    purpose: str
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    allowed_capabilities: tuple[str, ...]
    prohibited_effects: tuple[str, ...]
    handoff_to: tuple[str, ...]
    may_dispatch: bool

    @classmethod
    def from_dict(cls, value: dict) -> "RoleManifest":
        required = {
            "id", "identity", "purpose", "inputs", "outputs",
            "allowed_capabilities", "prohibited_effects", "handoff_to",
            "may_dispatch",
        }
        missing = required - value.keys()
        if missing:
            raise ValueError(f"role manifest missing {sorted(missing)}")
        if value["may_dispatch"] is not False:
            raise ValueError("compliance role manifests must set may_dispatch=false")
        return cls(
            id=value["id"], identity=value["identity"], purpose=value["purpose"],
            inputs=tuple(value["inputs"]), outputs=tuple(value["outputs"]),
            allowed_capabilities=tuple(value["allowed_capabilities"]),
            prohibited_effects=tuple(value["prohibited_effects"]),
            handoff_to=tuple(value["handoff_to"]), may_dispatch=False,
        )


def role_manifests() -> tuple[RoleManifest, ...]:
    """Load the eight packaged, host-neutral role contracts."""
    directory = files("a2a_compliance").joinpath("roles")
    manifests = []
    for path in sorted(directory.iterdir(), key=lambda p: p.name):
        if path.name.endswith(".json"):
            manifests.append(RoleManifest.from_dict(json.loads(path.read_text(encoding="utf-8"))))
    return tuple(manifests)


def _tool(repo: str, name: str, *, required: bool = True) -> Capability:
    return Capability(repo, CapabilityKind.TOOL, name, required)


def _skill(repo: str, name: str, *, required: bool = False) -> Capability:
    return Capability(repo, CapabilityKind.SKILL, name, required)


def _contract(repo: str, *, required: bool = True) -> Capability:
    return Capability(repo, CapabilityKind.CONTRACT, repo, required)


def _distribution(repo: str) -> Capability:
    return Capability(repo, CapabilityKind.DISTRIBUTION, repo, False)


# This is an integration manifest, not a second implementation of the family.
# Every public Loomground repository has exactly one owning role.  Callable logic
# is referenced by its published tool/skill name; data/spec repositories are
# consumed as contracts; packaging surfaces are distributions.
COMPLIANCE_ROLES: tuple[ComplianceRole, ...] = (
    ComplianceRole("conductor", "Own the control plan, governance boundary and hand-offs.", (
        _contract("loomground"),
        _contract("loomground-governance"),
        _contract("loomground-workspace"),
        _contract("loomground-vertical", required=False),
        _contract("skill-governance-block"),
        _contract("loomground-ref", required=False),
        _contract("a2a-compliance"),
        _distribution("loomground-plugins"),
        _distribution("loomground-patchbay"),
        _distribution("loomground-mcp"),
        _skill("loomground", "loomground"),
    )),
    ComplianceRole("evidence-grounder", "Acquire, normalise and span-ground evidence.", (
        _tool("loomground-ingest", "ingest_text"),
        _tool("loomground-versum", "versum_index"),
        _skill("loomground-ingest", "loomground-ingest"),
        _skill("loomground-versum", "loomground-kg"),
    )),
    ComplianceRole("policy-compiler", "Compile written policy and reject unresolved conflicts.", (
        _tool("policy-compiler", "policy_compile"),
        _tool("policy-compiler", "policy_check"),
        _skill("policy-compiler", "policy-compiler"),
    )),
    ComplianceRole("language-panel", "Preserve factual, modal, normative and legal-language facets.", (
        _tool("loomground-factual", "factual_lower"),
        _tool("loomground-epistemic", "epistemic_extract"),
        _tool("loomground-deontic", "deontic_parse"),
        _tool("loomground-deontic", "deontic_conflicts"),
        _tool("loomground-topos", "topos_parse"),
        _tool("loomground-norm", "norm_extract"),
        _contract("loomground-legal", required=False),
        _skill("loomground-factual", "factual"),
        _skill("loomground-epistemic", "epistemic"),
        _skill("loomground-deontic", "deontic"),
        _skill("loomground-topos", "topos"),
        _skill("loomground-norm", "norm"),
    )),
    ComplianceRole("decision-verifier", "Evaluate the patch and independently verify the bounded verdict.", (
        _tool("loomground-solver", "solver_evaluate"),
        _tool("loomground-solver", "solver_verify"),
        _skill("loomground-solver", "analyse-risks"),
    )),
    ComplianceRole("oversight-assessor", "Find the limiting term, autonomy ceiling and review material.", (
        _tool("loomground-brief", "brief"),
        _tool("loomground-collapse", "collapse"),
        _tool("loomground-escalation", "escalation"),
        _tool("loomground-falsifiability", "falsifiability"),
        _tool("loomground-mandate", "mandate"),
        _tool("loomground-proxy", "proxy"),
        _contract("oversight-ladder"),
    )),
    ComplianceRole("runtime-controller", "Preview admission, containment, drift and privacy controls.", (
        _tool("loomground-lane", "lane_evaluate"),
        _tool("loomground-lock", "lock_text"),
        _tool("loomground-drift", "drift_breaker"),
        _tool("loomground-erasure", "erasure_sweep"),
        _tool("privacy-shield", "privacy_scan"),
        _skill("privacy-shield", "privacy-shield"),
    )),
    ComplianceRole("assurance-recorder", "Verify the decision record and reconcile duties and effects.", (
        _tool("governance-certification", "govcert_verify"),
        _tool("5d-nd", "nd_digest"),
        _tool("oversight-certificate", "oversight_issue"),
        _tool("oversight-certificate", "oversight_verify"),
        _tool("enforcement-posture", "enforcement_compare"),
        _tool("effect-reconciliation", "effect_reconcile"),
        _tool("norm-freshness", "norm_freshness"),
        _tool("obligation-discharge", "obligation_admit"),
        _tool("loomground-audit-chain", "audit_chain_verify"),
        _tool("evidence-emitter", "evidence_emit"),
        _tool("evidence-emitter", "evidence_verify"),
        _skill("evidence-emitter", "evidence-emitter"),
    )),
)

LOOMGROUND_REPOSITORIES = frozenset(
    repo for role in COMPLIANCE_ROLES for repo in role.repositories
)


@dataclass(frozen=True)
class CapabilityInventory:
    """Capabilities exposed by the host's MCP/plugin/skill installation."""

    tools: frozenset[str] = frozenset()
    skills: frozenset[str] = frozenset()
    contracts: frozenset[str] = frozenset()
    distributions: frozenset[str] = frozenset()

    @classmethod
    def from_iterables(
        cls, *, tools: Iterable[str] = (), skills: Iterable[str] = (),
        contracts: Iterable[str] = (), distributions: Iterable[str] = (),
    ) -> "CapabilityInventory":
        return cls(*(frozenset(v) for v in (tools, skills, contracts, distributions)))

    def has(self, capability: Capability) -> bool:
        available = {
            CapabilityKind.TOOL: self.tools,
            CapabilityKind.SKILL: self.skills,
            CapabilityKind.CONTRACT: self.contracts,
            CapabilityKind.DISTRIBUTION: self.distributions,
        }[capability.kind]
        return capability.name in available


@dataclass(frozen=True)
class ControlRequest:
    context: GroundingContext
    target_kind: str
    governance: GovernanceBlock
    profile: TeamProfile = TeamProfile.LOOMGROUND
    require_tools: tuple[str, ...] = ()
    require_skills: tuple[str, ...] = ()


@dataclass(frozen=True)
class RoleStep:
    role: str
    purpose: str
    consumes: tuple[str, ...]
    missing_required: tuple[str, ...]
    missing_supporting: tuple[str, ...]


@dataclass(frozen=True)
class ControlPlan:
    profile: TeamProfile
    maker_id: str
    target_kind: str
    steps: tuple[RoleStep, ...]
    ruling: SteerRuling
    ready: bool
    disposition: str
    missing_required: tuple[str, ...]
    missing_supporting: tuple[str, ...]
    obligations: tuple[str, ...]
    grounding_result: Optional[GroundingResult] = None
    recommended_action: str = ACTION_ROUTE_HUMAN
    action_digest: str = ""
    repository_coverage: frozenset[str] = field(
        default=LOOMGROUND_REPOSITORIES, init=False,
    )


class ComplianceTeam:
    """Create a fail-closed, side-effect-free plan for a host orchestrator."""

    def __init__(self, inventory: Optional[CapabilityInventory] = None):
        self.inventory = inventory or CapabilityInventory()

    def plan(
        self, request: ControlRequest, *,
        grounding_result: Optional[GroundingResult] = None,
    ) -> ControlPlan:
        ruling = request.governance.rule(request.target_kind)
        steps: list[RoleStep] = []
        required: list[str] = []
        supporting: list[str] = []

        if request.profile is TeamProfile.LOOMGROUND:
            for role in COMPLIANCE_ROLES:
                missing_required = tuple(
                    c.key for c in role.capabilities if c.required and not self.inventory.has(c)
                )
                missing_supporting = tuple(
                    c.key for c in role.capabilities if not c.required and not self.inventory.has(c)
                )
                required.extend(missing_required)
                supporting.extend(missing_supporting)
                steps.append(RoleStep(
                    role.id, role.purpose,
                    tuple(c.key for c in role.capabilities),
                    missing_required, missing_supporting,
                ))

            for name in request.require_tools:
                if name not in self.inventory.tools:
                    required.append(f"tool:{name}")
            for name in request.require_skills:
                if name not in self.inventory.skills:
                    required.append(f"skill:{name}")

        missing_required = tuple(dict.fromkeys(required))
        missing_supporting = tuple(dict.fromkeys(supporting))
        boundary_ready = ruling.decision is SteerDecision.STEER
        assessed = grounding_result is not None or request.profile is TeamProfile.PROTOCOL
        ready = boundary_ready and not missing_required and assessed

        if ruling.decision is SteerDecision.REFUSE:
            disposition = "refuse"
        elif ruling.decision is SteerDecision.ROUTE_HUMAN:
            disposition = ACTION_ROUTE_HUMAN
        elif missing_required:
            disposition = ACTION_ROUTE_HUMAN
        elif grounding_result is None and request.profile is TeamProfile.LOOMGROUND:
            disposition = ACTION_ROUTE_HUMAN
        else:
            disposition = grounding_result.recommended_action if grounding_result else "advisory"

        action_subject = {
            "maker_id": request.context.maker_id,
            "target_kind": request.target_kind,
            "proposed_action": request.context.proposed_action,
        }
        # One canonical digest implementation (RFC 8785 JCS) for every wire
        # and in-process digest in this package; team.py no longer runs its
        # own json.dumps(sort_keys=True) hash, which silently diverges from
        # JCS on some numeric literals (e.g. 1e20).
        action_digest = canonical.digest_hex(action_subject)

        return ControlPlan(
            profile=request.profile,
            maker_id=request.context.maker_id,
            target_kind=request.target_kind,
            steps=tuple(steps),
            ruling=ruling,
            ready=ready,
            disposition=disposition,
            missing_required=missing_required,
            missing_supporting=missing_supporting,
            obligations=tuple(request.governance.obligations),
            grounding_result=grounding_result,
            recommended_action=(grounding_result.recommended_action
                                if grounding_result else ACTION_ROUTE_HUMAN),
            action_digest=action_digest,
        )

    def assess(self, request: ControlRequest, grounding_result: GroundingResult) -> ControlPlan:
        """Bind externally consumed grounding output to the inert control plan."""
        return self.plan(request, grounding_result=grounding_result)
