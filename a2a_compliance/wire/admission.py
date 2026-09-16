"""E2 — admission and permit issuance (plan: 'Admission and approval').

Replaces preview-only folding (`lifecycle.enforce_preview`, left intact for
E0/E1 callers) with a VERIFIED admission decision over signed wire receipts,
and, only on ADMITTED, a signed `ExecutionPermit`. This module never trusts
a receipt or approval field before it has passed `wire.verification.verify`
against an injected `TrustStore` (and, if supplied, `RevocationStore`) --
that is the E2 upgrade over E0's preview folding, which trusted receipt
objects outright.

State-machine mapping (plan: 'State machine'):
  - a `prohibited` kind (or one outside the governance block's declared
    boundary) is REFUSED -- never a permit, even with a valid approval,
    because the ruling is decided and returned before an approval is ever
    examined;
  - a `reserved` kind is REVIEW_REQUIRED unless it carries a matching,
    verified, authorized `HumanApprovalReceipt`;
  - `plan.ready` is not consulted at all here -- it answers "may
    orchestration begin", not "is this admitted"; this module recomputes
    the governance ruling and the receipt/approval checks from the ground
    up rather than trusting `plan.ready` or `plan.ruling`, so `ready` alone
    can never admit;
  - only `ADMITTED` may reach `issue_permit`; `REVIEW_REQUIRED`/`REFUSED`
    never produce a permit.

Fixed trust boundary: `admit()`/`issue_permit()` decide and (on admission)
build a signed permit; neither dispatches, executes, or fabricates an
approval -- an approval only ever arrives already-built via the `approval`
parameter, never synthesised here. `issue_permit()` needs a signer,
injected as an `Issuer` (`key_id` + `identity` + a `sign(dict) -> str`
callable) so this package never embeds or requires a production key;
`dev_issuer()` builds a TEST-ONLY one on `wire.signing.dev_sign_subject`
over an ephemeral dev keypair, exactly as E1's own conformance vectors do.

Role separation enforced here: an `Issuer` may not also be the approver it
relies on for the same permit (identity or key_id match is rejected) --
plan: "Policy authors, approvers, tool executors and assurance signers are
distinct identities. One identity may not satisfy incompatible roles in one
run." The remaining separations (policy-author vs. tool-executor,
tool-executor vs. assurance-signer, and the real oversight-ladder rung
model behind `ApproverAuthority`) are deferred to their owning repositories
(`oversight-ladder` and E3/E4) -- not decided here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Iterable, Optional, Protocol

from ..governance_block import GovernanceBlock, SteerDecision
from ..lifecycle import PREFLIGHT_TOOLS
from ..team import ControlPlan, TeamProfile
from . import canonical
from .trust import RevocationStore, TrustStore
from .verification import NonceStore, verify


class AdmissionDecision(str, Enum):
    ADMITTED = "ADMITTED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    REFUSED = "REFUSED"


@dataclass(frozen=True)
class AdmissionResult:
    decision: AdmissionDecision
    action_digest: str
    kind: str
    reasons: tuple[str, ...] = ()
    approval_reservations: tuple[str, ...] = ()


class ApproverAuthority(Protocol):
    """Injected port standing in for the real oversight-ladder rung/role
    model (plan repository: `oversight-ladder`). Deployment configuration,
    never read from an approval's own payload -- an approval claiming a
    role does not thereby grant it, exactly like `TrustStore.resolve`."""

    def authorizes(
        self, kind: str, approver_id: Optional[str], approver_role: Optional[str],
    ) -> bool: ...


class InMemoryApproverAuthority:
    """TEST-ONLY placeholder ApproverAuthority. Not durable; never use in a
    host. Maps a reserved `kind` to the set of roles authorized to approve
    it; an approver_id/role absent from that set (or either field empty) is
    unauthorized -- fail-closed, no wildcard default."""

    def __init__(self) -> None:
        self._by_kind: dict[str, frozenset[str]] = {}

    def allow(self, kind: str, role: str) -> None:
        self._by_kind[kind] = self._by_kind.get(kind, frozenset()) | {role}

    def authorizes(
        self, kind: str, approver_id: Optional[str], approver_role: Optional[str],
    ) -> bool:
        if not approver_id or not approver_role:
            return False
        return approver_role in self._by_kind.get(kind, frozenset())


@dataclass(frozen=True)
class Issuer:
    """A permit signer, injected by the host. `sign` receives the
    unsigned-permit subject dict (as `wire.signing.pae_bytes` would build it)
    and must return the base64 `signature` field value. a2a-compliance core
    never embeds or requires a production key: a host wires its own signer
    (e.g. KMS-backed) behind this same shape; `dev_issuer` below is the
    TEST-ONLY convenience for conformance vectors."""

    key_id: str
    identity: str
    sign: Callable[[dict], str]


def dev_issuer(key_id: str, identity: str, private_key_bytes: bytes) -> Issuer:
    """TEST-ONLY. `wire.signing.dev_sign_subject` is itself documented as a
    dev-only signer (see that module); calling it here, and only here,
    keeps `cryptography` out of this module's import until a caller
    actually builds a dev issuer."""
    from . import signing

    return Issuer(
        key_id=key_id, identity=identity,
        sign=lambda subject: signing.dev_sign_subject(subject, private_key_bytes),
    )


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _index_and_verify(
    plan: ControlPlan,
    receipts: Iterable[dict],
    *,
    trust_store: TrustStore,
    revocation_store: Optional[RevocationStore],
    now: Optional[datetime],
) -> tuple[dict[str, dict], tuple[str, ...]]:
    """VERIFY every StageReceipt through E1 `verify()` before trusting any
    of its fields, then bind it to this plan's action_digest and dedupe by
    capability. Anything that fails any of those is reported as invalid and
    excluded from the index -- never trusted partially."""
    indexed: dict[str, dict] = {}
    invalid: list[str] = []
    for receipt in receipts:
        if not isinstance(receipt, dict):
            invalid.append("receipt is not a JSON object")
            continue
        result = verify(
            receipt, "StageReceipt",
            trust_store=trust_store, revocation_store=revocation_store, now=now,
        )
        label = receipt.get("capability", "?")
        if not result.ok:
            invalid.append(f"{label}: " + "; ".join(result.errors))
            continue
        if receipt.get("action_digest") != plan.action_digest:
            invalid.append(f"{label}: action_digest does not match this plan")
            continue
        key = str(label).removeprefix("tool:")
        if key in indexed:
            invalid.append(f"{key}: duplicate receipt")
            continue
        indexed[key] = receipt
    return indexed, tuple(invalid)


def _approval_findings(
    plan: ControlPlan,
    kind: str,
    approval: Optional[dict],
    *,
    approver_authority: Optional[ApproverAuthority],
    trust_store: TrustStore,
    revocation_store: Optional[RevocationStore],
    now: Optional[datetime],
) -> tuple[list[str], tuple[str, ...]]:
    """Reserved-kind gate: an approval counts only once it VERIFIES (E1),
    is bound to this exact action_digest, and its approver is authorized
    for `kind` by the injected `ApproverAuthority`. Never fabricated: if
    `approval` is None, this always reports a finding -- there is no path
    that manufactures one."""
    reasons: list[str] = []
    if approval is None:
        return [f"{kind!r} is reserved and requires a HumanApprovalReceipt; none was provided"], ()

    result = verify(
        approval, "HumanApprovalReceipt",
        trust_store=trust_store, revocation_store=revocation_store, now=now,
    )
    if not result.ok:
        return ["approval receipt failed verification: " + "; ".join(result.errors)], ()

    if approval.get("permitted_action_digest") != plan.action_digest:
        return ["approval is not bound to this action (permitted_action_digest mismatch)"], ()

    approver = approval.get("approver") or {}
    approver_id, approver_role = approver.get("id"), approver.get("role")
    if approver_authority is None or not approver_authority.authorizes(kind, approver_id, approver_role):
        reasons.append(
            f"approver {approver_id!r}/{approver_role!r} is not authorized for reserved kind {kind!r}"
        )
        return reasons, ()

    if approval.get("scope") not in ("next-action", "session"):
        return ["approval scope is not a recognised value"], ()

    return [], tuple(approval.get("reservations") or ())


def admit(
    plan: ControlPlan,
    stage_receipts: Iterable[dict],
    *,
    governance: GovernanceBlock,
    trust_store: TrustStore,
    revocation_store: Optional[RevocationStore] = None,
    approval: Optional[dict] = None,
    approver_authority: Optional[ApproverAuthority] = None,
    acknowledged_obligations: Iterable[str] = (),
    now: Optional[datetime] = None,
) -> AdmissionResult:
    """Decide ADMITTED / REVIEW_REQUIRED / REFUSED. Fail-closed: any
    ambiguity (missing, unverified, mismatched or incomplete input) lands on
    REVIEW_REQUIRED, never ADMITTED; a `prohibited`/undeclared kind is
    REFUSED before anything else -- including `approval` -- is even
    inspected, so a valid approval can never rescue a prohibited kind."""
    kind = plan.target_kind
    # Re-derive the ruling from the governance block directly (plan:
    # 'GovernanceBlock.rule(kind)') rather than trusting `plan.ruling` --
    # this function must be safe to call on a plan it did not itself build.
    ruling = governance.rule(kind)

    if ruling.decision is SteerDecision.REFUSE:
        return AdmissionResult(AdmissionDecision.REFUSED, plan.action_digest, kind, (ruling.reason,))

    reasons: list[str] = []
    reservations: tuple[str, ...] = ()

    if ruling.decision is SteerDecision.ROUTE_HUMAN:
        approval_reasons, reservations = _approval_findings(
            plan, kind, approval,
            approver_authority=approver_authority, trust_store=trust_store,
            revocation_store=revocation_store, now=now,
        )
        reasons.extend(approval_reasons)
    elif ruling.decision is not SteerDecision.STEER:
        reasons.append(f"unrecognised governance ruling {ruling.decision!r}")

    indexed, invalid = _index_and_verify(
        plan, stage_receipts,
        trust_store=trust_store, revocation_store=revocation_store, now=now,
    )
    required = PREFLIGHT_TOOLS if plan.profile is TeamProfile.LOOMGROUND else ()
    missing = tuple(name for name in required if name not in indexed)
    unresolved = tuple(
        name for name in required if name in indexed and indexed[name].get("status") in {"OPEN", "ERROR"}
    )
    failed = tuple(
        name for name in required if name in indexed and indexed[name].get("status") == "NOT_SATISFIED"
    )
    if invalid:
        reasons.append("invalid preflight receipt(s): " + "; ".join(invalid))
    if missing:
        reasons.append("missing preflight receipt(s): " + ", ".join(missing))
    if unresolved:
        reasons.append("open/erroneous preflight receipt(s): " + ", ".join(unresolved))
    if failed:
        reasons.append("failed preflight receipt(s): " + ", ".join(failed))

    unacknowledged = tuple(o for o in plan.obligations if o not in set(acknowledged_obligations))
    if unacknowledged:
        reasons.append("unacknowledged obligation(s): " + ", ".join(unacknowledged))

    if reasons:
        return AdmissionResult(AdmissionDecision.REVIEW_REQUIRED, plan.action_digest, kind, tuple(reasons))

    return AdmissionResult(
        AdmissionDecision.ADMITTED, plan.action_digest, kind,
        approval_reservations=reservations,
    )


@dataclass(frozen=True)
class PermitIssueResult:
    ok: bool
    permit: Optional[dict] = None
    reasons: tuple[str, ...] = ()


def issue_permit(
    admission: AdmissionResult,
    *,
    issuer: Issuer,
    enforcement_grade: str,
    adapter: str,
    run_id: str,
    nonce: str,
    expires_at: datetime,
    nonce_store: NonceStore,
    constraints: Optional[dict] = None,
    approval: Optional[dict] = None,
    issued_at: Optional[datetime] = None,
    schema_version: str = "1.0.0",
) -> PermitIssueResult:
    """Build and sign an `ExecutionPermit` -- ONLY when `admission.decision`
    is ADMITTED. Never dispatches; this is the only object that later
    authorizes E3's executor. `nonce` is single-use: rejected if already
    consumed via `nonce_store`, and recorded here (not before) so a failed
    attempt never burns it."""
    if admission.decision is not AdmissionDecision.ADMITTED:
        return PermitIssueResult(False, None, (
            f"admission decision is {admission.decision.value}, not ADMITTED "
            "-- no permit may be issued",
        ))

    if approval is not None:
        approver = approval.get("approver") or {}
        if issuer.identity == approver.get("id") or issuer.key_id == approval.get("key_id"):
            return PermitIssueResult(False, None, (
                "role separation: the permit issuer identity/key must differ "
                "from the approver identity/key for the same run",
            ))

    if nonce_store.seen(run_id, nonce):
        return PermitIssueResult(False, None, ("nonce reuse: (run_id, nonce) already consumed",))

    merged_constraints = dict(constraints or {})
    if admission.approval_reservations:
        # A verified approver's reservations must always reach the permit --
        # a caller-supplied `constraints["reservations"]` must never shadow
        # or silently drop them (that would let a host strip a human's
        # attached safety condition from the object E3 later trusts).
        merged_constraints["reservations"] = list(admission.approval_reservations)

    issued = _as_utc(issued_at or datetime.now(timezone.utc))
    permit = {
        "schema_version": schema_version,
        "type": "ExecutionPermit",
        "issuer": issuer.identity,
        "issued_at": issued.isoformat(),
        "expires_at": _as_utc(expires_at).isoformat(),
        "run_id": run_id,
        "nonce": nonce,
        "key_id": issuer.key_id,
        "action_digest": admission.action_digest,
        "enforcement_grade": enforcement_grade,
        "adapter": adapter,
        "constraints": merged_constraints,
    }
    permit["subject_digest"] = canonical.subject_digest(permit)
    permit["signature"] = issuer.sign(permit)

    nonce_store.record(run_id, nonce)
    return PermitIssueResult(True, permit, ())
