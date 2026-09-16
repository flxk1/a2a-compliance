"""E5 -- portable conformance kit and enforcement-grade profile contract
(plan: 'E5 -- Distribution and platform profiles'; the HOST-NEUTRAL half of
that slice only -- `loomground-mcp`'s validation-only tools, `loomground-
plugins`' installation pins, the stdio/HTTP transport surface and
`loomground-workspace`/`loomground-vertical` overlays are the OUT-OF-SCOPE
distribution half, sequenced into another repository/session after the
a2a-compliance E1-E4 releases land -- plan: 'Repository ownership').

`run_conformance` drives the FULL governed pipeline -- `admission.admit` ->
`admission.issue_permit` -> `executor.consume_and_execute` -> `reconciliation.
reconcile` -> `certification.certify` -- over injected ports, exactly the same
way `examples/subprocess_adapter.py`'s own conformance tests already do, but
host-neutral and reusable: any host adapter can inject ITS OWN `TrustStore`/
`NonceStore`/`RevocationStore`/`ExecutorPort`/signers via `ConformancePorts`
and get back a structured `ConformanceReport` proving that the enforcement
proxy (`executor.consume_and_execute`) rejects a missing, tampered, reused,
expired, revoked or argument-mutated permit with NO effect -- "the same
end-to-end vectors a fresh install must pass" (plan: 'E5 exit').

That is necessarily narrower than the plan's full `mediated` grade (plan:
'Outcome'), which has two clauses: (a) "every governed tool is reachable
only through an enforcement proxy" -- no alternate path -- and (b) "bypass
is tested and treated as a deployment failure". This in-process kit can
only ever exercise the injected `ExecutorPort` THROUGH `consume_and_execute`
itself, so it structurally CANNOT observe whether a host's own deployment
also exposes that same tool through some other, out-of-band path (clause a)
-- only whether THIS gate, once reached, rejects a bad permit (clause b).
`ConformanceReport.bypass_rejected` reports clause (b) alone, honestly
scoped; see `Profile` below for how clause (a) is folded in as an explicit
host attestation rather than silently assumed.

No host effect of its own (hard constraint): this module never dispatches,
executes, signs with a production key, or touches a network/subprocess/file
directly. `InMemoryConformanceExecutor` is a purely in-memory default
`ExecutorPort`; a real deployment injects its own (e.g. `examples.
subprocess_adapter.GovernedEchoExecutor`) via `ConformancePorts.executor` or
`dev_conformance_ports(executor=...)`.

`Profile` is the enforcement-grade contract (plan: 'Outcome' -- advisory /
mediated / platform, "the protocol must report its actual grade"): a claimed
grade is checked against the report's OBSERVED grade, never taken on faith.
`mediated` requires BOTH clauses: `bypass_rejected` (re-derived from
`report.scenarios` directly, never trusted off a bare flag -- see
`_mediation_verified`) for clause (b), AND an explicit host attestation,
`no_alternate_path_attested`, for clause (a) -- the kit cannot observe that
one itself, so it is never assumed true by default. `platform` needs both of
those PLUS `platform_boundary_attested` (the host validates permits at its
own separate action boundary -- a third topology fact this kit also cannot
observe). A claim above what was actually observed is downgraded
(`reported_grade`) or refused outright (`assert_claim`), never honoured; no
attestation ever overrides an actual bypass failure. This formalises and
CORRECTS `examples/subprocess_adapter.py`'s own `enforcement_grade()`
self-check (plan: "a bypassable adapter cannot claim `mediated` or
`platform`") as a reusable contract every deployment can share -- that
self-check alone proves clause (b) only, exactly like this kit's
`bypass_rejected`; a real adapter still owes its own structural, host-side
proof of clause (a) (e.g. `test_no_other_public_path_to_the_governed_executor`
in `tests/test_e3_subprocess_adapter.py`) before attesting it here.

Named `conformance_kit.py` / `run_conformance` (not `conformance.py` /
`conformance`) to avoid the submodule/function name-collision class this
package already hit once (see `wire/__init__.py`'s docstring and the E3
commit that fixed `wire/verify.py` -> `wire/verification.py`) -- same reason
`reconciliation.py`/`certification.py` are named the way they are.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from ..governance_block import GovernanceBlock
from ..grounding import ACTION_NO_STEER, GroundingContext, GroundingResult
from ..lifecycle import PREFLIGHT_TOOLS, TOOL_OWNERS
from ..team import COMPLIANCE_ROLES as TEAM_ROLES
from ..team import CapabilityInventory, ComplianceTeam, ControlPlan, ControlRequest
from . import canonical
from .admission import (
    AdmissionDecision,
    ApproverAuthority,
    InMemoryApproverAuthority,
    Issuer,
    admit,
    dev_issuer,
    issue_permit,
)
from .certification import FreshnessPort, InMemoryFreshness, certify
from .executor import ExecutionOutcome, ExecutorPort, bind_constraints, consume_and_execute
from .obligations import issue_discharge_receipt
from .reconciliation import ObservedEffects, reconcile
from .signing import generate_dev_keypair
from .trust import ANY, InMemoryRevocationStore, InMemoryTrustStore, RevocationStore, TrustStore
from .verification import InMemoryNonceStore, NonceStore, verify

NORMAL_KIND = "conformance:normal"
RESERVED_KIND = "conformance:reserved"
PROHIBITED_KIND = "conformance:prohibited"
GOVERNED_TOOL = "conformance:tool"
DEFAULT_APPROVER_ROLE = "rung-2"
DEFAULT_OBLIGATION_ID = "conformance:obligation"
DEFAULT_MANDATORY_SOURCE = "conformance:source"

# One fixed, host-neutral governance boundary declaring exactly the three
# kinds every vector below needs (normal/reserved/prohibited) -- the VECTORS
# are what must stay identical across deployments, not a host's own policy.
GOVERNANCE = GovernanceBlock.from_dict({
    "actions": [{"kind": NORMAL_KIND}],
    "reserved": [{"kind": RESERVED_KIND, "by": "human"}],
    "prohibited": [PROHIBITED_KIND],
})

GRADES: tuple[str, ...] = ("advisory", "mediated", "platform")


@dataclass(frozen=True)
class ConformancePorts:
    """Everything a deployment injects to run the kit against ITSELF. The
    six `Issuer`s stand in for six distinct signing identities (plan: role
    separation) -- a host may point several at the same real KMS as long as
    the underlying identities/keys stay distinct, exactly like E2-E4's own
    role-separation checks require. Never construct this by hand for a
    self-test; use `dev_conformance_ports()`."""

    trust_store: TrustStore
    revocation_store: RevocationStore
    nonce_store: NonceStore
    executor: ExecutorPort
    approver_authority: ApproverAuthority
    freshness: FreshnessPort
    stage_signer: Issuer
    approval_signer: Issuer
    permit_issuer: Issuer
    tool_recorder: Issuer
    reconciler: Issuer
    discharger: Issuer
    certifier: Issuer
    approver_role: str = DEFAULT_APPROVER_ROLE


@dataclass(frozen=True)
class ScenarioResult:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class ConformanceReport:
    """`bypass_rejected` is an INFORMATIONAL summary (set by `run_conformance`
    from its own `scenarios`) that the mediation vectors passed -- plan
    clause (b) only. It is never sufficient by itself to claim `mediated`
    (clause (a), no-alternate-path, is a host structural fact this kit
    cannot observe -- see `Profile`), and `Profile` does not even trust this
    field: it re-derives the same fact from `scenarios` itself via
    `_mediation_verified`, so a hand-built report cannot bless a grade by
    setting this flag without the scenarios to back it."""

    scenarios: tuple[ScenarioResult, ...]
    bypass_rejected: bool
    certificate: Optional[dict] = None

    @property
    def ok(self) -> bool:
        return all(s.passed for s in self.scenarios)

    def failures(self) -> tuple[ScenarioResult, ...]:
        return tuple(s for s in self.scenarios if not s.passed)


class GradeClaimRejected(Exception):
    """Raised by `Profile.assert_claim` when a claimed enforcement grade
    exceeds what `run_conformance` actually observed for this deployment.
    Fail-closed: a claim above the observed grade is refused, never
    silently honoured (plan: "a bypassable adapter cannot claim `mediated`
    or `platform`")."""


@dataclass(frozen=True)
class Profile:
    """The enforcement-grade profile contract. Neither `mediated` nor
    `platform` is ever inferred from `run_conformance` alone: the plan's
    `mediated` grade has TWO clauses -- (a) the governed tool is reachable
    ONLY through the enforcement proxy (no alternate path), and (b) bypass
    is tested and rejected -- and this kit can only ever OBSERVE (b) (see
    `conformance_kit`'s module docstring for why (a) is structurally
    unobservable in-process). `no_alternate_path_attested` is the host's
    own explicit attestation of (a); it is REQUIRED for `mediated`, exactly
    the same way `platform_boundary_attested` (the host validating permits
    at its own, separate action boundary -- a third topology fact this kit
    also cannot observe) is required, on top of both of those, for
    `platform`. Neither attestation ever overrides an actual bypass
    failure -- `observed_grade` checks the re-derived scenario evidence
    FIRST, before either attestation is even consulted."""

    claimed_grade: str
    report: ConformanceReport
    no_alternate_path_attested: bool = False
    platform_boundary_attested: bool = False

    def __post_init__(self) -> None:
        if self.claimed_grade not in GRADES:
            raise ValueError(f"unknown enforcement grade: {self.claimed_grade!r}")

    @property
    def observed_grade(self) -> str:
        # Re-derived from the actual scenario results, never trusted off a
        # bare `report.bypass_rejected` flag -- a hand-built report cannot
        # bless a grade without the scenarios to back it (see
        # `_mediation_verified`).
        if not _mediation_verified(self.report.scenarios):
            return "advisory"
        if not self.no_alternate_path_attested:
            # Clause (b) alone: the proxy rejects bad permits, but without
            # the host attesting no-alternate-path, `mediated` cannot be
            # honestly claimed (plan clause (a) is unproven).
            return "advisory"
        if self.platform_boundary_attested:
            return "platform"
        return "mediated"

    @property
    def verified(self) -> bool:
        return GRADES.index(self.claimed_grade) <= GRADES.index(self.observed_grade)

    def reported_grade(self) -> str:
        """The grade this deployment may TRUTHFULLY report -- never higher
        than what `run_conformance` actually observed. A claim this
        deployment cannot support is downgraded, never honoured."""
        return self.claimed_grade if self.verified else self.observed_grade

    def assert_claim(self) -> None:
        """Hard-fail variant of the same guard: raise instead of silently
        downgrading, for a caller that wants to refuse a deployment outright
        rather than merely report a lower grade."""
        if not self.verified:
            raise GradeClaimRejected(
                f"claimed enforcement grade {self.claimed_grade!r} exceeds the "
                f"observed grade {self.observed_grade!r} for this deployment -- "
                "refused, not honoured"
            )


class InMemoryConformanceExecutor:
    """Default, host-neutral `ExecutorPort`: a deterministic, purely
    in-memory effect -- no subprocess, network or file access, so the kit
    itself never performs a host effect. A host conformance-testing its own
    deployment injects its own `ExecutorPort` (e.g. a subprocess adapter's
    executor) instead, via `ConformancePorts.executor` /
    `dev_conformance_ports(executor=...)`."""

    def __init__(
        self, *, executor_id: str = "executor:conformance-kit", executor_role: str = "tool-executor",
    ) -> None:
        self.executor_id = executor_id
        self.executor_role = executor_role

    def execute(self, tool: str, arguments: dict) -> ExecutionOutcome:
        return ExecutionOutcome(
            effect={"tool": tool, "arguments": arguments, "ok": True},
            executor_id=self.executor_id, executor_role=self.executor_role,
        )


class _RecordingExecutor:
    """Wraps an injected `ExecutorPort` so the kit can independently observe
    what a dispatch actually produced (the `ObservedEffects` contract:
    "not derived from the receipt itself") and count real calls (bypass
    detection) -- without adding any effect of its own, and without
    depending on anything beyond `ExecutorPort.execute`."""

    def __init__(self, inner: ExecutorPort) -> None:
        self._inner = inner
        self.call_count = 0
        self.last_outcome: Optional[ExecutionOutcome] = None

    def execute(self, tool: str, arguments: dict) -> ExecutionOutcome:
        self.call_count += 1
        outcome = self._inner.execute(tool, arguments)
        self.last_outcome = outcome
        return outcome


def dev_conformance_ports(*, executor: Optional[ExecutorPort] = None) -> ConformancePorts:
    """TEST-ONLY. Builds a complete, self-contained `ConformancePorts` over
    ephemeral dev Ed25519 keys (`wire.signing.generate_dev_keypair`) and
    in-memory stores -- exactly the E1-E4 conformance-vector convention
    (`tests/vectors/e1/`, `dev_issuer`). Never use in a host; a host builds
    its own durable trust/revocation/nonce stores and real signers, then
    constructs `ConformancePorts` directly. `executor` lets a caller keep
    every other default while substituting its own `ExecutorPort` to
    conformance-test a real deployment end to end."""
    keys = {
        name: generate_dev_keypair()
        for name in ("stage", "approval", "permit", "recorder", "reconciler", "discharger", "certifier")
    }
    trust_store = InMemoryTrustStore()
    trust_store.add("key-conformance-stage", keys["stage"][1], frozenset({"StageReceipt"}), frozenset({ANY}))
    trust_store.add("key-conformance-approval", keys["approval"][1], frozenset({"HumanApprovalReceipt"}), frozenset())
    trust_store.add("key-conformance-permit", keys["permit"][1], frozenset({"ExecutionPermit"}), frozenset())
    trust_store.add("key-conformance-recorder", keys["recorder"][1], frozenset({"ToolReceipt"}), frozenset())
    trust_store.add("key-conformance-reconciler", keys["reconciler"][1], frozenset({"Reconciliation"}), frozenset())
    trust_store.add(
        "key-conformance-discharger", keys["discharger"][1], frozenset({"ObligationDischargeReceipt"}), frozenset(),
    )
    trust_store.add("key-conformance-certifier", keys["certifier"][1], frozenset({"OversightCertificate"}), frozenset())

    approver_authority = InMemoryApproverAuthority()
    approver_authority.allow(RESERVED_KIND, DEFAULT_APPROVER_ROLE)

    def _dev(name: str, identity: str) -> Issuer:
        return dev_issuer(f"key-conformance-{name}", identity, keys[name][0])

    return ConformancePorts(
        trust_store=trust_store,
        revocation_store=InMemoryRevocationStore(),
        nonce_store=InMemoryNonceStore(),
        executor=executor if executor is not None else InMemoryConformanceExecutor(),
        approver_authority=approver_authority,
        freshness=InMemoryFreshness(),
        stage_signer=_dev("stage", "conformance:stage"),
        approval_signer=_dev("approval", "conformance:approver"),
        permit_issuer=_dev("permit", "conformance:permit-issuer"),
        tool_recorder=_dev("recorder", "conformance:tool-recorder"),
        reconciler=_dev("reconciler", "conformance:reconciler"),
        discharger=_dev("discharger", "conformance:discharger"),
        certifier=_dev("certifier", "conformance:certifier"),
    )


# --- plan/receipt/approval construction (host-neutral vectors) -------------

def _full_inventory() -> CapabilityInventory:
    tools, skills, contracts, distributions = set(), set(), set(), set()
    for role in TEAM_ROLES:
        for cap in role.capabilities:
            {"tool": tools, "skill": skills, "contract": contracts,
             "distribution": distributions}[cap.kind.value].add(cap.name)
    return CapabilityInventory.from_iterables(
        tools=tools, skills=skills, contracts=contracts, distributions=distributions,
    )


def _build_plan(kind: str) -> ControlPlan:
    request = ControlRequest(
        GroundingContext(maker_id="conformance-maker", proposed_action={"bearer": "conformance-maker", "action": kind}),
        kind, GOVERNANCE,
    )
    result = GroundingResult([], None, ACTION_NO_STEER, "a2a_compliance.wire.conformance_kit")
    return ComplianceTeam(_full_inventory()).assess(request, result)


def _stage_receipts(plan: ControlPlan, stage_signer: Issuer, *, run_id: str, issued_at: datetime, expires_at: datetime) -> list[dict]:
    receipts = []
    for name in PREFLIGHT_TOOLS:
        role = TOOL_OWNERS[name]
        base = {
            "schema_version": "1.0.0", "type": "StageReceipt",
            "issuer": f"issuer:{role}",
            "issued_at": issued_at.isoformat(), "expires_at": expires_at.isoformat(),
            "run_id": run_id, "nonce": f"{run_id}:stage:{name}",
            "key_id": stage_signer.key_id, "role": role, "capability": f"tool:{name}",
            "status": "SATISFIED", "action_digest": plan.action_digest,
            "input_digest": f"input:{name}", "output_digest": f"output:{name}", "reason": "",
        }
        base["subject_digest"] = canonical.subject_digest(base)
        base["signature"] = stage_signer.sign(base)
        receipts.append(base)
    return receipts


def _approval(
    plan: ControlPlan, approval_signer: Issuer, *, approver_role: str, run_id: str,
    issued_at: datetime, expires_at: datetime, reservations: tuple[str, ...] = (),
) -> dict:
    base = {
        "schema_version": "1.0.0", "type": "HumanApprovalReceipt",
        "issuer": f"issuer:{approval_signer.identity}",
        "issued_at": issued_at.isoformat(), "expires_at": expires_at.isoformat(),
        "run_id": run_id, "nonce": f"{run_id}:approval",
        "key_id": approval_signer.key_id,
        "approver": {"id": approval_signer.identity, "role": approver_role},
        "permitted_action_digest": plan.action_digest,
        "scope": "next-action", "reservations": list(reservations),
    }
    base["subject_digest"] = canonical.subject_digest(base)
    base["signature"] = approval_signer.sign(base)
    return base


# --- the positive scenario: a complete governed run certifies --------------

def _scenario_positive(ports: ConformancePorts, recorder: _RecordingExecutor, reference: datetime, far_future: datetime, run_id: str):
    plan = _build_plan(NORMAL_KIND)
    receipts = _stage_receipts(plan, ports.stage_signer, run_id=run_id, issued_at=reference, expires_at=far_future)
    admission = admit(
        plan, receipts, governance=GOVERNANCE, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, now=reference,
    )
    if admission.decision is not AdmissionDecision.ADMITTED:
        return False, f"admission was {admission.decision.value}: {admission.reasons}", None

    arguments = {"conformance": "positive", "run_id": run_id}
    permit_result = issue_permit(
        admission, issuer=ports.permit_issuer, enforcement_grade="mediated", adapter="conformance-kit",
        run_id=run_id, nonce=f"{run_id}:permit", expires_at=far_future, nonce_store=ports.nonce_store,
        constraints=bind_constraints(GOVERNED_TOOL, arguments), issued_at=reference,
    )
    if not permit_result.ok:
        return False, f"permit issuance failed: {permit_result.reasons}", None
    permit = permit_result.permit

    exec_result = consume_and_execute(
        permit, tool=GOVERNED_TOOL, arguments=arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:dispatch", revocation_store=ports.revocation_store, now=reference,
    )
    if not exec_result.ok:
        return False, f"execution failed: {exec_result.reasons}", None
    receipt = exec_result.receipt

    observed = ObservedEffects(effects={canonical.subject_digest(receipt): recorder.last_outcome.effect})
    recon_result = reconcile(
        permit, [receipt], observed, trust_store=ports.trust_store, revocation_store=ports.revocation_store,
        signer=ports.reconciler, run_id=run_id, nonce=f"{run_id}:recon", now=reference,
    )
    if not recon_result.ok or recon_result.reconciliation.get("certified") is not True:
        return False, f"reconciliation did not certify: {recon_result.reasons or recon_result.reconciliation}", None

    discharge = issue_discharge_receipt(
        DEFAULT_OBLIGATION_ID, permit["action_digest"], discharger=ports.discharger,
        run_id=run_id, nonce=f"{run_id}:discharge", expires_at=far_future, issued_at=reference,
    )
    cert_result = certify(
        permit, [receipt], recon_result.reconciliation, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, discharge_receipts=[discharge],
        blocking_obligations=[DEFAULT_OBLIGATION_ID], mandatory_sources=[DEFAULT_MANDATORY_SOURCE],
        freshness=ports.freshness, signer=ports.certifier, run_id=run_id, nonce=f"{run_id}:cert", now=reference,
    )
    if not cert_result.ok:
        return False, f"certification failed: {cert_result.reasons}", None

    verified = verify(
        cert_result.certificate, "OversightCertificate",
        trust_store=ports.trust_store, revocation_store=ports.revocation_store, now=reference,
    )
    if not verified.ok:
        return False, f"issued certificate does not itself verify: {verified.errors}", None
    return True, "full governed run produced one verifying OversightCertificate", cert_result.certificate


# --- negative scenarios: each must be OBSERVED to fail closed --------------

def _scenario_prohibited_never_admits(ports, recorder, reference, far_future, run_id):
    plan = _build_plan(PROHIBITED_KIND)
    receipts = _stage_receipts(plan, ports.stage_signer, run_id=run_id, issued_at=reference, expires_at=far_future)
    approval = _approval(
        plan, ports.approval_signer, approver_role=ports.approver_role,
        run_id=run_id, issued_at=reference, expires_at=far_future,
    )
    result = admit(
        plan, receipts, governance=GOVERNANCE, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, approval=approval,
        approver_authority=ports.approver_authority, now=reference,
    )
    ok = result.decision is AdmissionDecision.REFUSED
    return ok, f"decision={result.decision.value} (expected REFUSED even with a valid approval)"


def _scenario_reserved_without_approval_never_admits(ports, recorder, reference, far_future, run_id):
    plan = _build_plan(RESERVED_KIND)
    receipts = _stage_receipts(plan, ports.stage_signer, run_id=run_id, issued_at=reference, expires_at=far_future)
    result = admit(
        plan, receipts, governance=GOVERNANCE, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, approver_authority=ports.approver_authority, now=reference,
    )
    ok = result.decision is AdmissionDecision.REVIEW_REQUIRED
    return ok, f"decision={result.decision.value} (expected REVIEW_REQUIRED with no approval)"


def _scenario_ready_alone_never_admits(ports, recorder, reference, far_future, run_id):
    plan = _build_plan(NORMAL_KIND)
    result = admit(
        plan, [], governance=GOVERNANCE, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, now=reference,
    )
    ok = bool(plan.ready) and result.decision is not AdmissionDecision.ADMITTED
    return ok, f"plan.ready={plan.ready}, decision={result.decision.value} (ready alone must never admit)"


def _scenario_non_admitted_permit_never_issued(ports, recorder, reference, far_future, run_id):
    plan = _build_plan(RESERVED_KIND)
    receipts = _stage_receipts(plan, ports.stage_signer, run_id=run_id, issued_at=reference, expires_at=far_future)
    admission = admit(
        plan, receipts, governance=GOVERNANCE, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, approver_authority=ports.approver_authority, now=reference,
    )
    if admission.decision is AdmissionDecision.ADMITTED:
        return False, "admission was unexpectedly ADMITTED without an approval -- cannot exercise this vector"
    permit_result = issue_permit(
        admission, issuer=ports.permit_issuer, enforcement_grade="mediated", adapter="conformance-kit",
        run_id=run_id, nonce=f"{run_id}:permit", expires_at=far_future, nonce_store=ports.nonce_store,
        issued_at=reference,
    )
    ok = (not permit_result.ok) and permit_result.permit is None
    return ok, f"admission={admission.decision.value}, permit issued={permit_result.ok}"


def _scenario_bypass_missing_permit(ports, recorder, reference, far_future, run_id):
    before = recorder.call_count
    result = consume_and_execute(
        {}, tool=GOVERNED_TOOL, arguments={"conformance": "bypass-missing", "run_id": run_id},
        trust_store=ports.trust_store, nonce_store=ports.nonce_store, executor=recorder,
        signer=ports.tool_recorder, dispatch_id=f"{run_id}:bypass-missing",
        revocation_store=ports.revocation_store, now=reference,
    )
    ok = (not result.ok) and recorder.call_count == before
    return ok, f"execute ok={result.ok}, executor call delta={recorder.call_count - before}"


def _scenario_bypass_tampered_permit(ports, recorder, reference, far_future, run_id):
    plan = _build_plan(NORMAL_KIND)
    receipts = _stage_receipts(plan, ports.stage_signer, run_id=run_id, issued_at=reference, expires_at=far_future)
    admission = admit(
        plan, receipts, governance=GOVERNANCE, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, now=reference,
    )
    if admission.decision is not AdmissionDecision.ADMITTED:
        return False, f"could not admit a plan to build a tamperable permit: {admission.reasons}"
    arguments = {"conformance": "bypass-tampered", "run_id": run_id}
    permit_result = issue_permit(
        admission, issuer=ports.permit_issuer, enforcement_grade="mediated", adapter="conformance-kit",
        run_id=run_id, nonce=f"{run_id}:permit", expires_at=far_future, nonce_store=ports.nonce_store,
        constraints=bind_constraints(GOVERNED_TOOL, arguments), issued_at=reference,
    )
    if not permit_result.ok:
        return False, f"could not issue a permit to tamper with: {permit_result.reasons}"
    tampered = dict(permit_result.permit)
    tampered["run_id"] = f"{run_id}:attacker-supplied"  # subject changes, signature stays stale

    before = recorder.call_count
    result = consume_and_execute(
        tampered, tool=GOVERNED_TOOL, arguments=arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:bypass-tampered", revocation_store=ports.revocation_store, now=reference,
    )
    ok = (not result.ok) and recorder.call_count == before
    return ok, f"execute ok={result.ok}, executor call delta={recorder.call_count - before}"


def _scenario_reuse_nonce_replay(ports, recorder, reference, far_future, run_id):
    plan = _build_plan(NORMAL_KIND)
    receipts = _stage_receipts(plan, ports.stage_signer, run_id=run_id, issued_at=reference, expires_at=far_future)
    admission = admit(
        plan, receipts, governance=GOVERNANCE, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, now=reference,
    )
    if admission.decision is not AdmissionDecision.ADMITTED:
        return False, f"could not admit a plan to test reuse: {admission.reasons}"
    arguments = {"conformance": "reuse", "run_id": run_id}
    permit_result = issue_permit(
        admission, issuer=ports.permit_issuer, enforcement_grade="mediated", adapter="conformance-kit",
        run_id=run_id, nonce=f"{run_id}:permit", expires_at=far_future, nonce_store=ports.nonce_store,
        constraints=bind_constraints(GOVERNED_TOOL, arguments), issued_at=reference,
    )
    if not permit_result.ok:
        return False, f"could not issue a permit to test reuse: {permit_result.reasons}"
    permit = permit_result.permit

    before = recorder.call_count
    first = consume_and_execute(
        permit, tool=GOVERNED_TOOL, arguments=arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:reuse-1", revocation_store=ports.revocation_store, now=reference,
    )
    after_first = recorder.call_count
    second = consume_and_execute(
        permit, tool=GOVERNED_TOOL, arguments=arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:reuse-2", revocation_store=ports.revocation_store, now=reference,
    )
    after_second = recorder.call_count
    ok = first.ok and after_first == before + 1 and (not second.ok) and after_second == after_first
    return ok, (
        f"first ok={first.ok}, second ok={second.ok}, "
        f"executor calls={after_first - before}/{after_second - after_first}"
    )


def _scenario_drift_expired_permit(ports, recorder, reference, far_future, run_id):
    plan = _build_plan(NORMAL_KIND)
    receipts = _stage_receipts(plan, ports.stage_signer, run_id=run_id, issued_at=reference, expires_at=far_future)
    admission = admit(
        plan, receipts, governance=GOVERNANCE, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, now=reference,
    )
    if admission.decision is not AdmissionDecision.ADMITTED:
        return False, f"could not admit a plan to test drift: {admission.reasons}"
    arguments = {"conformance": "drift-expiry", "run_id": run_id}
    short_expiry = reference + timedelta(minutes=1)
    permit_result = issue_permit(
        admission, issuer=ports.permit_issuer, enforcement_grade="mediated", adapter="conformance-kit",
        run_id=run_id, nonce=f"{run_id}:permit", expires_at=short_expiry, nonce_store=ports.nonce_store,
        constraints=bind_constraints(GOVERNED_TOOL, arguments), issued_at=reference,
    )
    if not permit_result.ok:
        return False, f"could not issue a short-lived permit: {permit_result.reasons}"

    before = recorder.call_count
    result = consume_and_execute(
        permit_result.permit, tool=GOVERNED_TOOL, arguments=arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:drift-expiry", revocation_store=ports.revocation_store,
        now=reference + timedelta(hours=1),
    )
    ok = (not result.ok) and recorder.call_count == before
    return ok, f"execute ok={result.ok} after expiry, executor call delta={recorder.call_count - before}"


def _scenario_drift_revoked_run(ports, recorder, reference, far_future, run_id):
    plan = _build_plan(NORMAL_KIND)
    receipts = _stage_receipts(plan, ports.stage_signer, run_id=run_id, issued_at=reference, expires_at=far_future)
    admission = admit(
        plan, receipts, governance=GOVERNANCE, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, now=reference,
    )
    if admission.decision is not AdmissionDecision.ADMITTED:
        return False, f"could not admit a plan to test revocation drift: {admission.reasons}"
    arguments = {"conformance": "drift-revoked", "run_id": run_id}
    permit_result = issue_permit(
        admission, issuer=ports.permit_issuer, enforcement_grade="mediated", adapter="conformance-kit",
        run_id=run_id, nonce=f"{run_id}:permit", expires_at=far_future, nonce_store=ports.nonce_store,
        constraints=bind_constraints(GOVERNED_TOOL, arguments), issued_at=reference,
    )
    if not permit_result.ok:
        return False, f"could not issue a permit to revoke: {permit_result.reasons}"

    # Scoped to THIS scenario's run_id only -- never a shared signer key --
    # so later scenarios in the same run_conformance() call stay unaffected.
    ports.revocation_store.revoke("run", run_id, reference - timedelta(seconds=1))

    before = recorder.call_count
    result = consume_and_execute(
        permit_result.permit, tool=GOVERNED_TOOL, arguments=arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:drift-revoked", revocation_store=ports.revocation_store, now=reference,
    )
    ok = (not result.ok) and recorder.call_count == before
    return ok, f"execute ok={result.ok} after this run_id was revoked, executor call delta={recorder.call_count - before}"


def _scenario_argument_mutation(ports, recorder, reference, far_future, run_id):
    plan = _build_plan(NORMAL_KIND)
    receipts = _stage_receipts(plan, ports.stage_signer, run_id=run_id, issued_at=reference, expires_at=far_future)
    admission = admit(
        plan, receipts, governance=GOVERNANCE, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, now=reference,
    )
    if admission.decision is not AdmissionDecision.ADMITTED:
        return False, f"could not admit a plan to test argument mutation: {admission.reasons}"
    permitted_arguments = {"conformance": "argument-mutation", "run_id": run_id}
    permit_result = issue_permit(
        admission, issuer=ports.permit_issuer, enforcement_grade="mediated", adapter="conformance-kit",
        run_id=run_id, nonce=f"{run_id}:permit", expires_at=far_future, nonce_store=ports.nonce_store,
        constraints=bind_constraints(GOVERNED_TOOL, permitted_arguments), issued_at=reference,
    )
    if not permit_result.ok:
        return False, f"could not issue a permit to mutate arguments against: {permit_result.reasons}"

    mutated_arguments = {**permitted_arguments, "mutated": True}
    before = recorder.call_count
    result = consume_and_execute(
        permit_result.permit, tool=GOVERNED_TOOL, arguments=mutated_arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:argument-mutation", revocation_store=ports.revocation_store, now=reference,
    )
    ok = (not result.ok) and recorder.call_count == before
    return ok, f"execute ok={result.ok} with mutated arguments, executor call delta={recorder.call_count - before}"


def _scenario_mismatched_observed_effects(ports, recorder, reference, far_future, run_id):
    plan = _build_plan(NORMAL_KIND)
    receipts = _stage_receipts(plan, ports.stage_signer, run_id=run_id, issued_at=reference, expires_at=far_future)
    admission = admit(
        plan, receipts, governance=GOVERNANCE, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, now=reference,
    )
    if admission.decision is not AdmissionDecision.ADMITTED:
        return False, f"could not admit a plan to test reconciliation: {admission.reasons}"
    arguments = {"conformance": "mismatched-effect", "run_id": run_id}
    permit_result = issue_permit(
        admission, issuer=ports.permit_issuer, enforcement_grade="mediated", adapter="conformance-kit",
        run_id=run_id, nonce=f"{run_id}:permit", expires_at=far_future, nonce_store=ports.nonce_store,
        constraints=bind_constraints(GOVERNED_TOOL, arguments), issued_at=reference,
    )
    if not permit_result.ok:
        return False, f"could not issue a permit to dispatch: {permit_result.reasons}"
    exec_result = consume_and_execute(
        permit_result.permit, tool=GOVERNED_TOOL, arguments=arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:dispatch", revocation_store=ports.revocation_store, now=reference,
    )
    if not exec_result.ok:
        return False, f"could not dispatch to test reconciliation: {exec_result.reasons}"
    receipt = exec_result.receipt

    # Host independently observed something DIFFERENT from what the tool
    # itself self-reported -- a successful ToolReceipt exit is not, by
    # itself, sufficient evidence (plan: E4 exit).
    observed = ObservedEffects(effects={
        canonical.subject_digest(receipt): {"conformance": "tampered-observation", "run_id": run_id},
    })
    recon_result = reconcile(
        permit_result.permit, [receipt], observed, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, signer=ports.reconciler,
        run_id=run_id, nonce=f"{run_id}:recon", now=reference,
    )
    if not recon_result.ok:
        return False, f"reconcile itself failed unexpectedly: {recon_result.reasons}"
    cert_result = certify(
        permit_result.permit, [receipt], recon_result.reconciliation, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, signer=ports.certifier,
        run_id=run_id, nonce=f"{run_id}:cert", now=reference,
    )
    ok = (recon_result.reconciliation.get("certified") is False) and (cert_result.ok is False)
    return ok, f"reconciliation.certified={recon_result.reconciliation.get('certified')}, certify ok={cert_result.ok}"


def _scenario_fabricated_discharge(ports, recorder, reference, far_future, run_id):
    plan = _build_plan(NORMAL_KIND)
    receipts = _stage_receipts(plan, ports.stage_signer, run_id=run_id, issued_at=reference, expires_at=far_future)
    admission = admit(
        plan, receipts, governance=GOVERNANCE, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, now=reference,
    )
    if admission.decision is not AdmissionDecision.ADMITTED:
        return False, f"could not admit a plan to test obligation discharge: {admission.reasons}"
    arguments = {"conformance": "fabricated-discharge", "run_id": run_id}
    permit_result = issue_permit(
        admission, issuer=ports.permit_issuer, enforcement_grade="mediated", adapter="conformance-kit",
        run_id=run_id, nonce=f"{run_id}:permit", expires_at=far_future, nonce_store=ports.nonce_store,
        constraints=bind_constraints(GOVERNED_TOOL, arguments), issued_at=reference,
    )
    if not permit_result.ok:
        return False, f"could not issue a permit to dispatch: {permit_result.reasons}"
    exec_result = consume_and_execute(
        permit_result.permit, tool=GOVERNED_TOOL, arguments=arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:dispatch", revocation_store=ports.revocation_store, now=reference,
    )
    if not exec_result.ok:
        return False, f"could not dispatch to test obligation discharge: {exec_result.reasons}"
    receipt = exec_result.receipt
    observed = ObservedEffects(effects={canonical.subject_digest(receipt): recorder.last_outcome.effect})
    recon_result = reconcile(
        permit_result.permit, [receipt], observed, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, signer=ports.reconciler,
        run_id=run_id, nonce=f"{run_id}:recon", now=reference,
    )
    if not recon_result.ok or recon_result.reconciliation.get("certified") is not True:
        return False, f"reconciliation did not cleanly certify: {recon_result.reasons or recon_result.reconciliation}"

    fabricated = dict(issue_discharge_receipt(
        DEFAULT_OBLIGATION_ID, permit_result.permit["action_digest"], discharger=ports.discharger,
        run_id=run_id, nonce=f"{run_id}:discharge", expires_at=far_future, issued_at=reference,
    ))
    fabricated["signature"] = ""  # fabricated/unsigned

    cert_result = certify(
        permit_result.permit, [receipt], recon_result.reconciliation, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, discharge_receipts=[fabricated],
        blocking_obligations=[DEFAULT_OBLIGATION_ID], signer=ports.certifier,
        run_id=run_id, nonce=f"{run_id}:cert", now=reference,
    )
    ok = (cert_result.ok is False) and any("not discharged" in r for r in cert_result.reasons)
    return ok, f"certify ok={cert_result.ok}, reasons={cert_result.reasons}"


# Scenarios whose PASS jointly evidences "bypass is tested and rejected"
# (plan: 'Outcome' -- the mediated grade). Admission-only vectors (prohibited/
# reserved/ready-alone/non-admitted-permit) and certification-honesty vectors
# (mismatched effects/fabricated discharge) are real guarantees too, but they
# are not what distinguishes `advisory` from `mediated` -- only whether the
# effect boundary itself can be bypassed is.
_MEDIATION_SCENARIOS: tuple[str, ...] = (
    "bypass_missing_permit_rejected", "bypass_tampered_permit_rejected",
    "reuse_nonce_replay_rejected", "drift_expired_permit_rejected",
    "drift_revoked_run_rejected", "argument_mutation_rejected",
)

def _mediation_verified(scenarios: tuple[ScenarioResult, ...]) -> bool:
    """The single source of truth for plan clause (b) ("bypass is tested
    and treated as a deployment failure"): the positive run certified AND
    every named mediation vector is PRESENT and passed. Computed fresh from
    `scenarios` every time it is called (by both `run_conformance`, to fill
    in the report's informational `bypass_rejected` field, and by `Profile.
    observed_grade`, which never trusts that field back) -- so an empty or
    tampered scenario list can never earn a passing result, only the
    honest `run_conformance` path can."""
    by_name = {s.name: s for s in scenarios}
    positive = by_name.get("positive_full_run_certifies")
    if positive is None or not positive.passed:
        return False
    return all(
        (scenario := by_name.get(name)) is not None and scenario.passed
        for name in _MEDIATION_SCENARIOS
    )


_NEGATIVE_SCENARIOS: tuple[tuple[str, Callable], ...] = (
    ("prohibited_action_never_admits", _scenario_prohibited_never_admits),
    ("reserved_without_approval_never_admits", _scenario_reserved_without_approval_never_admits),
    ("ready_alone_never_admits", _scenario_ready_alone_never_admits),
    ("non_admitted_permit_never_issued", _scenario_non_admitted_permit_never_issued),
    ("bypass_missing_permit_rejected", _scenario_bypass_missing_permit),
    ("bypass_tampered_permit_rejected", _scenario_bypass_tampered_permit),
    ("reuse_nonce_replay_rejected", _scenario_reuse_nonce_replay),
    ("drift_expired_permit_rejected", _scenario_drift_expired_permit),
    ("drift_revoked_run_rejected", _scenario_drift_revoked_run),
    ("argument_mutation_rejected", _scenario_argument_mutation),
    ("mismatched_observed_effects_not_certified", _scenario_mismatched_observed_effects),
    ("fabricated_discharge_not_certified", _scenario_fabricated_discharge),
)


def run_conformance(ports: ConformancePorts, *, now: Optional[datetime] = None) -> ConformanceReport:
    """Drive the positive scenario plus every negative scenario against
    `ports`, fail-closed reporting throughout: a scenario that raises is
    recorded as a failed vector, never an escaping exception. Each call uses
    a fresh random run-id prefix, so `run_conformance` may be called
    repeatedly against the same durable stores (e.g. in CI) without a false
    nonce/revocation collision between runs."""
    reference = now if now is not None else datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    far_future = reference + timedelta(hours=1)
    token = uuid.uuid4().hex[:12]
    recorder = _RecordingExecutor(ports.executor)

    scenarios: list[ScenarioResult] = []
    try:
        ok, detail, certificate = _scenario_positive(
            ports, recorder, reference, far_future, f"conformance-{token}-positive",
        )
    except Exception as exc:  # noqa: BLE001 -- fail-closed reporting, never a crash
        ok, detail, certificate = False, f"raised {exc!r}", None
    scenarios.append(ScenarioResult("positive_full_run_certifies", ok, detail))

    for name, scenario in _NEGATIVE_SCENARIOS:
        run_id = f"conformance-{token}-{name}"
        try:
            ok, detail = scenario(ports, recorder, reference, far_future, run_id)
        except Exception as exc:  # noqa: BLE001 -- fail-closed reporting, never a crash
            ok, detail = False, f"raised {exc!r}"
        scenarios.append(ScenarioResult(name, ok, detail))

    bypass_rejected = _mediation_verified(tuple(scenarios))
    return ConformanceReport(tuple(scenarios), bypass_rejected, certificate)
