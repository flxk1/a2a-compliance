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

from .. import envelope as env
from ..authority import Roster
from ..channel import ComplianceAgent
from ..governance_block import GovernanceBlock, sign_governance_block
from ..grounding import ACTION_NO_STEER, GroundingContext, GroundingResult
from ..lifecycle import PREFLIGHT_TOOLS, TOOL_OWNERS
from ..participant import ControlParticipant
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
from .signing import (
    cnf_jkt_for_public_key,
    dev_sign_proof_of_possession,
    dev_sign_subject,
    generate_dev_keypair,
)
from .trust import ANY, InMemoryRevocationStore, InMemoryTrustStore, RevocationStore, TrustStore
from .verification import InMemoryNonceStore, NonceStore, verify
from interfaces.a2a_control import Authority as ControlAuthority
from interfaces.a2a_control import Party, Verb

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
    # Quick win 5 -- sender-constrained permit: the ONE executor identity and
    # Ed25519 keypair every mediation-scenario permit is bound to via
    # aud/cnf. A host conformance-testing a real deployment wires these to
    # its own adapter's identity and signing key.
    executor_identity: str = "executor:conformance-kit"
    executor_public_key: bytes = b""
    executor_private_key: bytes = b""


@dataclass(frozen=True)
class ScenarioResult:
    name: str
    passed: bool
    detail: str
    # Quick win 10 -- machine-readable OWASP Agentic AI Top 10 (2026) id this
    # scenario's PASS evidences (ASI01-ASI10; see the one-line comment next
    # to each scenario's own entry in `_NEGATIVE_SCENARIOS`/`_POSITIVE_ASI`
    # for the why). Never inferred from the name string -- always carried
    # explicitly from the scenario's own definition, so a caller (and
    # `tests/test_conformance_asi_tags.py`) can check it without parsing
    # prose. Defaults to `""` ONLY so a hand-built `ScenarioResult` in an
    # existing test (predating this field) keeps constructing with its
    # original 3 positional args; every `ScenarioResult` `run_conformance`
    # itself produces always sets a real `ASIxx` id.
    asi: str = ""


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


class _InMemoryInbox:
    """Quick win 10 -- a purely in-memory duck-typed stand-in for `inbox.
    FileInbox`'s `put`/`poll` transport seam (the same seam `harness.py`'s
    own `HarnessTransport` duck-types against instead of subclassing). Both
    `ControlParticipant.checkpoint()` and `ComplianceAgent._send()`/
    `.collect_replies()` call ONLY `.put()`/`.poll()` on their injected
    inbox -- they never introspect its type -- so this satisfies the real
    control-channel seam exactly while keeping the control-channel
    scenarios below on the module's own no-host-effect invariant (never a
    real file, unlike the file-backed inbox `tests/test_control_channel_
    auth.py`/`tests/test_halt_approval.py` use for the same seam)."""

    def __init__(self) -> None:
        self._boxes: dict[str, list[dict]] = {}

    def put(self, to_actor: str, msg_wire: dict) -> int:
        box = self._boxes.setdefault(to_actor, [])
        box.append(msg_wire)
        return len(box) - 1

    def poll(self, actor: str) -> list[dict]:
        box = self._boxes.setdefault(actor, [])
        pending, self._boxes[actor] = box, []
        return pending


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

    executor_private_key, executor_public_key = generate_dev_keypair()

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
        executor_public_key=executor_public_key,
        executor_private_key=executor_private_key,
    )


def _cnf_for(ports: ConformancePorts) -> dict:
    """The `cnf` claim every sender-constrained permit in this kit issues:
    the RFC 7638 thumbprint of `ports`' own executor keypair."""
    return {"jkt": cnf_jkt_for_public_key(ports.executor_public_key)}


def _dev_proof(ports: ConformancePorts, permit: dict) -> dict:
    """The proof of possession the legitimate executor presents for
    `permit`: an Ed25519 signature by `ports.executor_private_key` over this
    exact permit's `(subject_digest, nonce)`."""
    return dev_sign_proof_of_possession(permit["subject_digest"], permit["nonce"], ports.executor_private_key)


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

# ASI10 Rogue Agents -- the positive run's PASS is the baseline every other
# scenario's rejection is contrasted against: it shows the ONLY way to reach
# a certified effect is through the mediated pipeline itself, never a rogue
# path around it.
_POSITIVE_ASI = "ASI10"


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
        aud=ports.executor_identity, cnf=_cnf_for(ports),
    )
    if not permit_result.ok:
        return False, f"permit issuance failed: {permit_result.reasons}", None
    permit = permit_result.permit

    exec_result = consume_and_execute(
        permit, tool=GOVERNED_TOOL, arguments=arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:dispatch", revocation_store=ports.revocation_store, now=reference,
        executor_identity=ports.executor_identity, proof_of_possession=_dev_proof(ports, permit),
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
        aud=ports.executor_identity, cnf=_cnf_for(ports),
    )
    if not permit_result.ok:
        return False, f"could not issue a permit to test reuse: {permit_result.reasons}"
    permit = permit_result.permit
    proof = _dev_proof(ports, permit)

    before = recorder.call_count
    first = consume_and_execute(
        permit, tool=GOVERNED_TOOL, arguments=arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:reuse-1", revocation_store=ports.revocation_store, now=reference,
        executor_identity=ports.executor_identity, proof_of_possession=proof,
    )
    after_first = recorder.call_count
    second = consume_and_execute(
        permit, tool=GOVERNED_TOOL, arguments=arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:reuse-2", revocation_store=ports.revocation_store, now=reference,
        executor_identity=ports.executor_identity, proof_of_possession=proof,
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
        aud=ports.executor_identity, cnf=_cnf_for(ports),
    )
    if not permit_result.ok:
        return False, f"could not issue a short-lived permit: {permit_result.reasons}"

    before = recorder.call_count
    result = consume_and_execute(
        permit_result.permit, tool=GOVERNED_TOOL, arguments=arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:drift-expiry", revocation_store=ports.revocation_store,
        now=reference + timedelta(hours=1),
        executor_identity=ports.executor_identity, proof_of_possession=_dev_proof(ports, permit_result.permit),
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
        aud=ports.executor_identity, cnf=_cnf_for(ports),
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
        executor_identity=ports.executor_identity, proof_of_possession=_dev_proof(ports, permit_result.permit),
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
        aud=ports.executor_identity, cnf=_cnf_for(ports),
    )
    if not permit_result.ok:
        return False, f"could not issue a permit to mutate arguments against: {permit_result.reasons}"

    mutated_arguments = {**permitted_arguments, "mutated": True}
    before = recorder.call_count
    result = consume_and_execute(
        permit_result.permit, tool=GOVERNED_TOOL, arguments=mutated_arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:argument-mutation", revocation_store=ports.revocation_store, now=reference,
        executor_identity=ports.executor_identity, proof_of_possession=_dev_proof(ports, permit_result.permit),
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
        aud=ports.executor_identity, cnf=_cnf_for(ports),
    )
    if not permit_result.ok:
        return False, f"could not issue a permit to dispatch: {permit_result.reasons}"
    exec_result = consume_and_execute(
        permit_result.permit, tool=GOVERNED_TOOL, arguments=arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:dispatch", revocation_store=ports.revocation_store, now=reference,
        executor_identity=ports.executor_identity, proof_of_possession=_dev_proof(ports, permit_result.permit),
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
        aud=ports.executor_identity, cnf=_cnf_for(ports),
    )
    if not permit_result.ok:
        return False, f"could not issue a permit to dispatch: {permit_result.reasons}"
    exec_result = consume_and_execute(
        permit_result.permit, tool=GOVERNED_TOOL, arguments=arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:dispatch", revocation_store=ports.revocation_store, now=reference,
        executor_identity=ports.executor_identity, proof_of_possession=_dev_proof(ports, permit_result.permit),
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


# --- quick win 5 negative scenarios: sender-constrained permit --------------

def _scenario_foreign_executor_rejected(ports, recorder, reference, far_future, run_id):
    """A permit sender-constrained to `ports.executor_identity`, but PRESENTED
    by a different executor identity (a valid proof of possession, just from
    the wrong caller) -- `aud` mismatch, rejected with no effect and the
    nonce left unspent; the legitimate executor can still consume it
    afterwards (proof the rejection never touched the nonce)."""
    plan = _build_plan(NORMAL_KIND)
    receipts = _stage_receipts(plan, ports.stage_signer, run_id=run_id, issued_at=reference, expires_at=far_future)
    admission = admit(
        plan, receipts, governance=GOVERNANCE, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, now=reference,
    )
    if admission.decision is not AdmissionDecision.ADMITTED:
        return False, f"could not admit a plan to test a foreign executor: {admission.reasons}"
    arguments = {"conformance": "foreign-executor", "run_id": run_id}
    permit_result = issue_permit(
        admission, issuer=ports.permit_issuer, enforcement_grade="mediated", adapter="conformance-kit",
        run_id=run_id, nonce=f"{run_id}:permit", expires_at=far_future, nonce_store=ports.nonce_store,
        constraints=bind_constraints(GOVERNED_TOOL, arguments), issued_at=reference,
        aud=ports.executor_identity, cnf=_cnf_for(ports),
    )
    if not permit_result.ok:
        return False, f"could not issue a sender-constrained permit: {permit_result.reasons}"
    permit = permit_result.permit
    proof = _dev_proof(ports, permit)

    before = recorder.call_count
    foreign = consume_and_execute(
        permit, tool=GOVERNED_TOOL, arguments=arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:foreign", revocation_store=ports.revocation_store, now=reference,
        executor_identity="executor:foreign-adapter", proof_of_possession=proof,
    )
    after_foreign = recorder.call_count
    legit = consume_and_execute(
        permit, tool=GOVERNED_TOOL, arguments=arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:legit", revocation_store=ports.revocation_store, now=reference,
        executor_identity=ports.executor_identity, proof_of_possession=proof,
    )
    after_legit = recorder.call_count
    ok = (
        (not foreign.ok) and after_foreign == before
        and legit.ok and after_legit == before + 1
    )
    return ok, (
        f"foreign executor ok={foreign.ok}, legitimate executor ok={legit.ok}, "
        f"executor calls={after_foreign - before}/{after_legit - after_foreign}"
    )


def _scenario_missing_proof_rejected(ports, recorder, reference, far_future, run_id):
    """A permit sender-constrained to `ports.executor_identity`, presented by
    the RIGHT identity but with no proof of possession at all -- rejected
    with no effect and the nonce left unspent; the same executor presenting
    a valid proof afterwards still succeeds (proof the rejection never
    touched the nonce)."""
    plan = _build_plan(NORMAL_KIND)
    receipts = _stage_receipts(plan, ports.stage_signer, run_id=run_id, issued_at=reference, expires_at=far_future)
    admission = admit(
        plan, receipts, governance=GOVERNANCE, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, now=reference,
    )
    if admission.decision is not AdmissionDecision.ADMITTED:
        return False, f"could not admit a plan to test a missing proof: {admission.reasons}"
    arguments = {"conformance": "missing-proof", "run_id": run_id}
    permit_result = issue_permit(
        admission, issuer=ports.permit_issuer, enforcement_grade="mediated", adapter="conformance-kit",
        run_id=run_id, nonce=f"{run_id}:permit", expires_at=far_future, nonce_store=ports.nonce_store,
        constraints=bind_constraints(GOVERNED_TOOL, arguments), issued_at=reference,
        aud=ports.executor_identity, cnf=_cnf_for(ports),
    )
    if not permit_result.ok:
        return False, f"could not issue a sender-constrained permit: {permit_result.reasons}"
    permit = permit_result.permit

    before = recorder.call_count
    missing = consume_and_execute(
        permit, tool=GOVERNED_TOOL, arguments=arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:missing-proof", revocation_store=ports.revocation_store, now=reference,
        executor_identity=ports.executor_identity, proof_of_possession=None,
    )
    after_missing = recorder.call_count
    legit = consume_and_execute(
        permit, tool=GOVERNED_TOOL, arguments=arguments, trust_store=ports.trust_store,
        nonce_store=ports.nonce_store, executor=recorder, signer=ports.tool_recorder,
        dispatch_id=f"{run_id}:legit", revocation_store=ports.revocation_store, now=reference,
        executor_identity=ports.executor_identity, proof_of_possession=_dev_proof(ports, permit),
    )
    after_legit = recorder.call_count
    ok = (
        (not missing.ok) and after_missing == before
        and legit.ok and after_legit == before + 1
    )
    return ok, (
        f"missing-proof ok={missing.ok}, legitimate proof ok={legit.ok}, "
        f"executor calls={after_missing - before}/{after_legit - after_missing}"
    )


# --- quick win 10 negative scenarios: the control-channel/governance/------
# --- provenance seams (OWASP Agentic AI Top 10, 2026) ----------------------

def _scenario_control_forged_sender_rejected(ports, recorder, reference, far_future, run_id):
    """Quick win 10 -- forged sender on the control channel. A `HOLD`
    envelope signed by a key NEVER registered in the maker's `TrustStore`
    (a forger who has no legitimate signing identity at all) must be
    rejected and NEVER applied -- exactly the seam `tests/
    test_control_channel_auth.py::test_forged_sender_not_applied_reported_
    accepted_false` already exercises against `ControlParticipant.
    checkpoint()` directly; this drives the identical seam in-process over
    `_InMemoryInbox` so the module stays file-free."""
    comp_actor, maker_id = f"{run_id}:comp", f"{run_id}:maker"
    _legit_priv, legit_pub = generate_dev_keypair()
    forger_priv, _forger_pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add(
        "key-comp-legit", legit_pub, frozenset({"A2AControlMessage"}), frozenset({"policy-compliance"}),
    )
    # key-forger is deliberately NEVER registered.
    maker = ControlParticipant(
        session_id=maker_id, inbox=_InMemoryInbox(), compliance_actor=comp_actor,
        trust_store=trust_store, nonce_store=InMemoryNonceStore(),
        state_provider=lambda include: {},
    )
    msg = env.new_message(
        from_=Party(actor=comp_actor, role="policy-compliance"),
        to=Party(actor=maker_id, role="maker"),
        verb=Verb.HOLD, body=env.hold_body("next-action"),
        authority=ControlAuthority(basis="role", role="policy-compliance", oversees=maker_id, reserved=False),
    )
    forged = env.stamp_and_sign(
        env.to_wire(msg), key_id="key-forger",
        sign=lambda d: dev_sign_subject(d, forger_priv), nonce=f"{run_id}:nonce",
    )
    maker.inbox.put(maker_id, forged)
    responses = maker.checkpoint()
    ok = (
        len(responses) == 1 and responses[0].verb is Verb.ACK
        and responses[0].body.get("accepted") is False and maker.is_held() is False
    )
    return ok, (
        f"responses={[(r.verb.value, r.body.get('accepted')) for r in responses]}, "
        f"held={maker.is_held()}"
    )


def _scenario_control_replayed_resume_rejected(ports, recorder, reference, far_future, run_id):
    """Quick win 10 -- replayed resume on the control channel. The identical
    signed `RESUME` envelope (same sender, same nonce) delivered a second
    time must be rejected on the second delivery -- the first delivery
    still applies normally. Same seam as `tests/test_control_channel_auth.
    py::test_replayed_nonce_rejected_on_second_delivery`."""
    comp_actor, maker_id = f"{run_id}:comp", f"{run_id}:maker"
    priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add("key-comp", pub, frozenset({"A2AControlMessage"}), frozenset({"policy-compliance"}))
    maker = ControlParticipant(
        session_id=maker_id, inbox=_InMemoryInbox(), compliance_actor=comp_actor,
        trust_store=trust_store, nonce_store=InMemoryNonceStore(),
        state_provider=lambda include: {},
    )
    msg = env.new_message(
        from_=Party(actor=comp_actor, role="policy-compliance"),
        to=Party(actor=maker_id, role="maker"),
        verb=Verb.RESUME, body=env.resume_body(f"{run_id}:hold"),
        authority=ControlAuthority(basis="role", role="policy-compliance", oversees=maker_id, reserved=False),
    )
    resume_wire = env.stamp_and_sign(
        env.to_wire(msg), key_id="key-comp",
        sign=lambda d: dev_sign_subject(d, priv), nonce=f"{run_id}:fixed-nonce",
    )
    maker.inbox.put(maker_id, resume_wire)
    first = maker.checkpoint()
    maker.inbox.put(maker_id, resume_wire)  # the identical envelope, delivered again
    second = maker.checkpoint()
    ok = (
        len(first) == 1 and first[0].body.get("accepted") is True
        and len(second) == 1 and second[0].body.get("accepted") is False
        and "replay" in (second[0].body.get("note") or "")
    )
    return ok, (
        f"first accepted={first[0].body.get('accepted')}, "
        f"second accepted={second[0].body.get('accepted')}, note={second[0].body.get('note')!r}"
    )


def _scenario_control_unapproved_halt_not_dispatched(ports, recorder, reference, far_future, run_id):
    """Quick win 10 -- unapproved halt. `ComplianceAgent.halt()` in
    AUTHENTICATED mode (a `TrustStore` configured) must never dispatch on
    `confirm=True` alone or with no approval at all -- a reserved act is
    surfaced to the human but NOT sent, exactly `tests/test_halt_approval.
    py::test_no_receipt_not_dispatched`'s seam, driven here over the same
    `ComplianceAgent.halt()` this kit's other scenarios never otherwise
    touch."""
    comp_actor, maker_id = f"{run_id}:comp", f"{run_id}:maker"
    _priv, pub = generate_dev_keypair()
    trust_store = InMemoryTrustStore()
    trust_store.add("key-approver", pub, frozenset({"HumanApprovalReceipt"}), frozenset())
    comp = ComplianceAgent(
        session_id=comp_actor, role="policy-compliance", inbox=_InMemoryInbox(),
        roster=Roster(), trust_store=trust_store,
    )
    result = comp.halt(maker_id, reason_ref="conformance-quick-win-10")
    ok = result.dispatched is False and result.surfaced_to_human is True
    return ok, (
        f"dispatched={result.dispatched}, surfaced_to_human={result.surfaced_to_human}, "
        f"denied_reason={result.denied_reason!r}"
    )


def _scenario_tampered_governance_block_not_admitted(ports, recorder, reference, far_future, run_id):
    """Quick win 10 -- tampered governance block. A `SignedGovernanceBlock`
    pins the ORIGINAL `GOVERNANCE` digest; `admit()` is then called against
    a widened block (the prohibition silently dropped after signing) that
    still hashes differently -- `admission._governance_block_findings`
    (quick win 9) must catch the digest mismatch and refuse admission,
    never trusting the block actually in force just because a signature
    exists somewhere for a DIFFERENT block."""
    plan = _build_plan(NORMAL_KIND)
    receipts = _stage_receipts(plan, ports.stage_signer, run_id=run_id, issued_at=reference, expires_at=far_future)
    policy_author_role = "policy-author"
    author_priv, author_pub = generate_dev_keypair()
    key_id = f"key-{run_id}-policy-author"
    # Registered under a run-scoped key_id -- never collides with the
    # stage/permit/... bindings `dev_conformance_ports` already installed
    # on this same shared `ports.trust_store`.
    ports.trust_store.add(key_id, author_pub, frozenset({"GovernanceBlock"}), frozenset({policy_author_role}))
    issuer = dev_issuer(key_id, f"policy:{run_id}-author", author_priv)
    signed = sign_governance_block(GOVERNANCE, key_id=issuer.key_id, identity=issuer.identity, sign=issuer.sign)
    tampered_governance = GovernanceBlock.from_dict({
        "actions": [{"kind": NORMAL_KIND}],
        "reserved": [{"kind": RESERVED_KIND, "by": "human"}],
        "prohibited": [],  # attacker silently dropped the prohibition after signing
    })
    admission = admit(
        plan, receipts, governance=tampered_governance, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, signed_governance_block=signed,
        policy_author_role=policy_author_role, now=reference,
    )
    ok = (
        admission.decision is not AdmissionDecision.ADMITTED
        and admission.governance_block_digest is None
        and any("does not match the pinned, signed digest" in r for r in admission.reasons)
    )
    return ok, f"decision={admission.decision.value}, reasons={admission.reasons}"


def _scenario_self_report_never_satisfies_admission(ports, recorder, reference, far_future, run_id):
    """Quick win 10 -- injection-provenance. `envelope.report_state_body` is
    the ONE existing provenance notion this package already has (SPEC
    §3.3): a maker's own account, ALWAYS stamped `provenance:'self-report'`,
    NEVER promoted to witnessed/observed evidence. This asserts both halves
    of that guarantee: (a) the stamp itself never drifts off
    `'self-report'`, and (b) even when that exact self-report body is
    smuggled into `admit()`'s stage-receipt list in place of a required
    preflight `StageReceipt`, `wire.verify` rejects it outright (it has
    neither the `StageReceipt` schema shape nor a trust-store-resolvable
    signature it could forge without a trusted key) and admission is never
    granted on its strength -- a maker's self-report can never satisfy an
    admission receipt."""
    self_report = env.report_state_body(claims=[{"claim": "conformance-injection-provenance"}])
    if self_report.get("provenance") != "self-report":
        return False, f"self-report body drifted off provenance='self-report': {self_report!r}"

    plan = _build_plan(NORMAL_KIND)
    legitimate = _stage_receipts(plan, ports.stage_signer, run_id=run_id, issued_at=reference, expires_at=far_future)
    dropped_capability = f"tool:{PREFLIGHT_TOOLS[0]}"
    forged_as_receipt = dict(self_report)
    forged_as_receipt.update({
        "run_id": run_id, "nonce": f"{run_id}:stage:forged-self-report",
        "action_digest": plan.action_digest, "capability": dropped_capability,
    })
    tainted = [r for r in legitimate if r["capability"] != dropped_capability]
    tainted.append(forged_as_receipt)  # the self-report smuggled in place of the missing receipt

    admission = admit(
        plan, tainted, governance=GOVERNANCE, trust_store=ports.trust_store,
        revocation_store=ports.revocation_store, now=reference,
    )
    ok = (
        admission.decision is not AdmissionDecision.ADMITTED
        and forged_as_receipt.get("provenance") == "self-report"
    )
    return ok, (
        f"decision={admission.decision.value}, reasons={admission.reasons}, "
        f"forged.provenance={forged_as_receipt.get('provenance')!r}"
    )


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


# Quick win 10 -- every entry now also carries a machine-readable OWASP
# Agentic AI Top 10 (2026) id (`ASI01`-`ASI10`), one-line-justified inline,
# for the specific attack/failure class THIS scenario's PASS evidences was
# rejected/refused. `tests/test_conformance_asi_tags.py` asserts every
# entry (and the positive scenario, see `_POSITIVE_ASI` above run_
# conformance) carries a valid id.
_NEGATIVE_SCENARIOS: tuple[tuple[str, Callable, str], ...] = (
    # ASI01 Agent Goal Hijack -- a prohibited kind must never be admitted by
    # smuggling a valid approval past a REFUSE ruling; that is exactly a
    # goal-hijack attempt against the declared governance boundary.
    ("prohibited_action_never_admits", _scenario_prohibited_never_admits, "ASI01"),
    # ASI03 Identity and Privilege Abuse -- a reserved (higher-privilege)
    # kind must stay unadmitted without a genuine approval; admitting it
    # anyway would be an unearned privilege escalation.
    ("reserved_without_approval_never_admits", _scenario_reserved_without_approval_never_admits, "ASI03"),
    # ASI10 Rogue Agents -- a plan's own self-declared `ready` flag must
    # never stand in for governance's own ADMITTED ruling; a plan cannot be
    # allowed to certify its own readiness as authorization.
    ("ready_alone_never_admits", _scenario_ready_alone_never_admits, "ASI10"),
    # ASI02 Tool Misuse -- no `ExecutionPermit` (the only thing that lets a
    # tool run at all) may ever be issued off a non-ADMITTED decision.
    ("non_admitted_permit_never_issued", _scenario_non_admitted_permit_never_issued, "ASI02"),
    # ASI05 Unexpected Code Execution -- dispatching a tool with NO permit
    # at all is the paradigmatic unauthorized-execution case; it must never
    # reach the executor.
    ("bypass_missing_permit_rejected", _scenario_bypass_missing_permit, "ASI05"),
    # ASI04 Agentic Supply Chain -- a permit mutated after issuance (its
    # signature now stale) is a tampered signed artifact; supply-chain
    # integrity of the authorization itself must hold.
    ("bypass_tampered_permit_rejected", _scenario_bypass_tampered_permit, "ASI04"),
    # ASI07 Insecure Inter-Agent Communication -- replaying a
    # once-consumed permit is a message-replay attack against the
    # executor's own inbound channel.
    ("reuse_nonce_replay_rejected", _scenario_reuse_nonce_replay, "ASI07"),
    # ASI08 Cascading Failures -- an expired permit consumed late is a
    # time-drift failure mode that must fail closed rather than cascade a
    # stale authorization into a live effect.
    ("drift_expired_permit_rejected", _scenario_drift_expired_permit, "ASI08"),
    # ASI03 Identity and Privilege Abuse -- a revoked run must lose its
    # standing privilege immediately; a permit issued under it must not
    # keep working past revocation.
    ("drift_revoked_run_rejected", _scenario_drift_revoked_run, "ASI03"),
    # ASI02 Tool Misuse -- dispatching a governed tool with arguments other
    # than the ones actually bound into the permit is exactly a misuse of
    # that tool call.
    ("argument_mutation_rejected", _scenario_argument_mutation, "ASI02"),
    # ASI06 Memory and Context Poisoning -- a tool's own self-reported
    # success must never be trusted uncritically; independently observed
    # effects that disagree must poison nothing downstream (no
    # certification).
    ("mismatched_observed_effects_not_certified", _scenario_mismatched_observed_effects, "ASI06"),
    # ASI09 Human-Agent Trust Exploitation -- fabricating an unsigned
    # obligation-discharge receipt is exploiting the certifier's trust in a
    # compliance artifact to claim a duty was satisfied when it was not.
    ("fabricated_discharge_not_certified", _scenario_fabricated_discharge, "ASI09"),
    # ASI03 Identity and Privilege Abuse -- a permit sender-constrained to
    # one executor identity presented by a DIFFERENT one is an identity
    # substitution attack.
    ("foreign_executor_rejected", _scenario_foreign_executor_rejected, "ASI03"),
    # ASI07 Insecure Inter-Agent Communication -- the right identity with
    # NO proof of possession at all is an unauthenticated inter-agent
    # message; the channel itself must demand the proof, not just the
    # claimed identity.
    ("missing_proof_rejected", _scenario_missing_proof_rejected, "ASI07"),
    # ASI07 Insecure Inter-Agent Communication -- a control-channel envelope
    # signed by a key with no trust-store standing at all (a forger with no
    # legitimate identity) must never be applied.
    ("control_forged_sender_rejected", _scenario_control_forged_sender_rejected, "ASI07"),
    # ASI07 Insecure Inter-Agent Communication -- the identical signed
    # control envelope delivered twice is a replay against the control
    # channel itself, distinct from the permit-replay vector above.
    ("control_replayed_resume_rejected", _scenario_control_replayed_resume_rejected, "ASI07"),
    # ASI09 Human-Agent Trust Exploitation -- dispatching a reserved halt
    # without a verified, distinct human's approval would exploit the
    # human-in-the-loop trust boundary the reserved-act gate exists to
    # protect.
    ("control_unapproved_halt_not_dispatched", _scenario_control_unapproved_halt_not_dispatched, "ASI09"),
    # ASI04 Agentic Supply Chain -- a governance/policy artifact widened
    # after it was signed is a tampered supply-chain input to the
    # admission decision itself.
    ("tampered_governance_block_not_admitted", _scenario_tampered_governance_block_not_admitted, "ASI04"),
    # ASI06 Memory and Context Poisoning -- an unverified maker self-report,
    # if it could satisfy an admission receipt, would poison the
    # governance decision with attacker-influenced, unwitnessed content.
    ("self_report_never_satisfies_admission", _scenario_self_report_never_satisfies_admission, "ASI06"),
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
    scenarios.append(ScenarioResult("positive_full_run_certifies", ok, detail, _POSITIVE_ASI))

    for name, scenario, asi in _NEGATIVE_SCENARIOS:
        run_id = f"conformance-{token}-{name}"
        try:
            ok, detail = scenario(ports, recorder, reference, far_future, run_id)
        except Exception as exc:  # noqa: BLE001 -- fail-closed reporting, never a crash
            ok, detail = False, f"raised {exc!r}"
        scenarios.append(ScenarioResult(name, ok, detail, asi))

    bypass_rejected = _mediation_verified(tuple(scenarios))
    return ConformanceReport(tuple(scenarios), bypass_rejected, certificate)
