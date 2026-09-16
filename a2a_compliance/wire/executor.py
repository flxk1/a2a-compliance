"""E3 -- mediated executor (plan: 'E3 -- Mediated executor').

`consume_and_execute` is the ONLY function in this package that stands
between an admitted, signed `ExecutionPermit` and a real effect. It decides
nothing new about admission (E2 already did that); it re-VERIFIES the permit
at the moment of execution -- catching drift (expiry/revocation that
happened after admission, before dispatch) -- checks that the tool call
actually being made matches the one the permit binds, atomically consumes
the permit's single-use nonce BEFORE the effect, and only then calls the
injected `ExecutorPort`. It builds and signs the resulting `ToolReceipt`.

Fixed trust boundary (plan): this module never dispatches, executes,
kills, erases, activates policy or uses a production signing key itself --
the actual effect lives ENTIRELY behind `ExecutorPort`, an injected port a
host implements (see `examples/subprocess_adapter.py` for the conformance
adapter; that module, not this one, is the only place in this repository
that ever calls `subprocess`). This module performs no subprocess, network,
dispatch, kill, erase, policy-activation or production-key use of its own.

Order of operations, exactly (plan: 'State machine' + this slice's exit
criterion):

    verify -> match -> atomic-consume -> execute -> receipt

1. `wire.verification.verify(permit, "ExecutionPermit", trust_store=...,
   revocation_store=..., now=...)` -- catches a missing/invalid/forged/
   wrong-key permit (bypass) AND a permit that was valid at admission but is
   now expired or revoked (drift). No permit, no verification.
2. The ACTUAL `(tool, arguments)` about to be executed must match what the
   permit binds via its `constraints` (see `bind_constraints` below): same
   tool name, same `arguments_digest`. A caller who mutates arguments after
   admission is rejected here (argument mutation) -- BEFORE anything is
   consumed or executed.
3. `nonce_store.consume(run_id, nonce)` -- atomic compare-and-set, single
   call site, strictly before `executor.execute` is ever reached. A second
   `consume_and_execute` call with the same permit fails here (reuse),
   whether or not step 4 already ran.
4. `executor.execute(tool, arguments)` -- the ONLY call in this whole
   module that can produce a real effect; entirely delegated to the
   injected port.
5. Build, canonicalise, digest and sign the `ToolReceipt` and return it.

A permit that fails any of steps 1-3 is rejected with NO call to
`executor.execute` and NO `ToolReceipt` produced -- there is no execution
without a valid, matching, freshly-consumed permit (bypass is impossible by
construction: nothing in this module, or in `a2a_compliance.wire` at large,
exposes a path to `ExecutorPort.execute` other than through this function).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Protocol

from . import canonical
from .admission import Issuer
from .trust import RevocationStore, TrustStore
from .verification import NonceStore, verify

DEFAULT_RECEIPT_TTL = timedelta(days=365)


@dataclass(frozen=True)
class ExecutionOutcome:
    """What a host's `ExecutorPort` reports back for one call. `effect` is
    an arbitrary JSON-safe dict describing the observed result (e.g.
    stdout/exit code for a subprocess adapter) -- this module only digests
    it, never interprets it. `executor_id`/`executor_role` identify the
    principal that actually ran the effect (plan: 'ToolReceipt' -- executor
    identity), reported by the host, never fabricated here."""

    effect: dict
    executor_id: str
    executor_role: str


class ExecutorPort(Protocol):
    """Injected, host-owned. The ONLY interface through which a real effect
    may occur. a2a-compliance core never implements this itself (fixed
    trust boundary) -- a real implementation (e.g. the subprocess
    conformance adapter) lives outside this package's core."""

    def execute(self, tool: str, arguments: dict) -> ExecutionOutcome: ...


@dataclass(frozen=True)
class ExecutionResult:
    ok: bool
    receipt: Optional[dict] = None
    reasons: tuple[str, ...] = ()


def bind_constraints(tool: str, arguments: dict, *, extra: Optional[dict] = None) -> dict:
    """Build the `ExecutionPermit.constraints` convention this module reads
    back in `consume_and_execute`: the permitted tool name and the RFC 8785
    digest of its permitted arguments. A host calls this when building the
    `constraints` argument to E2's `issue_permit` (this is a convention on
    top of that already-free-form field, not a change to E2's API/schema).
    `extra` may add lane/lock/drift or other admission-time constraints
    (plan: 'ExecutionPermit') alongside this binding; it must not use the
    `tool`/`arguments_digest` keys -- those are reserved by this binding."""
    if extra and ({"tool", "arguments_digest"} & extra.keys()):
        raise ValueError("extra constraints may not use the reserved 'tool'/'arguments_digest' keys")
    return {"tool": tool, "arguments_digest": canonical.digest_hex(arguments), **(extra or {})}


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def consume_and_execute(
    permit: dict,
    *,
    tool: str,
    arguments: dict,
    trust_store: TrustStore,
    nonce_store: NonceStore,
    executor: ExecutorPort,
    signer: Issuer,
    dispatch_id: str,
    revocation_store: Optional[RevocationStore] = None,
    now: Optional[datetime] = None,
    schema_version: str = "1.0.0",
    receipt_ttl: timedelta = DEFAULT_RECEIPT_TTL,
) -> ExecutionResult:
    """Verify `permit`, check it binds exactly `(tool, arguments)`,
    atomically consume its nonce, and ONLY THEN call `executor.execute`.
    Returns a signed `ToolReceipt` on success. Fail-closed: any rejection
    returns `ok=False` with no receipt and, critically, no call to
    `executor.execute` -- steps 1-3 all happen before the only line in this
    function that can produce a real effect.

    `now` is the verification reference time only (drift: a permit valid at
    admission but expired/revoked as of `now` is rejected) -- it does not
    stand in for the receipt's own `started_at`/`ended_at`, which are always
    the real wall-clock bracket around the `executor.execute` call."""
    if not isinstance(permit, dict):
        return ExecutionResult(False, None, ("permit is not a JSON object",))

    reference = _as_utc(now) if now is not None else datetime.now(timezone.utc)

    # 1. verify -- bypass (missing/invalid/forged/wrong-key permit) and
    # drift (valid at admission, stale/revoked now) are both caught here.
    verified = verify(
        permit, "ExecutionPermit",
        trust_store=trust_store, revocation_store=revocation_store, now=reference,
    )
    if not verified.ok:
        return ExecutionResult(False, None, verified.errors)

    grade = permit.get("enforcement_grade")
    if grade not in ("mediated", "platform"):
        return ExecutionResult(False, None, (
            f"enforcement_grade {grade!r} does not authorize mediated execution",
        ))

    # 2. match -- the actual (tool, arguments) must equal what the permit's
    # constraints bind (see bind_constraints); anything else is an argument
    # mutation (or a tool substitution), rejected before any consumption.
    constraints = permit.get("constraints")
    if not isinstance(constraints, dict):
        return ExecutionResult(False, None, ("permit constraints missing or not an object",))
    expected_tool = constraints.get("tool")
    expected_digest = constraints.get("arguments_digest")
    if not expected_tool or not expected_digest:
        return ExecutionResult(False, None, (
            "permit constraints do not bind a tool/arguments_digest -- nothing to match against",
        ))
    if tool != expected_tool:
        return ExecutionResult(False, None, (
            f"tool mismatch: permit binds {expected_tool!r}, requested {tool!r}",
        ))
    try:
        actual_digest = canonical.digest_hex(arguments)
    except (TypeError, ValueError) as exc:
        return ExecutionResult(False, None, (f"cannot canonicalise arguments: {exc}",))
    if actual_digest != expected_digest:
        return ExecutionResult(False, None, (
            "argument mutation: executed arguments digest does not match the permit's binding",
        ))

    # 3. atomic-consume -- strictly before the only line that can execute.
    run_id, nonce = permit.get("run_id"), permit.get("nonce")
    if not nonce_store.consume(run_id, nonce):
        return ExecutionResult(False, None, (
            "nonce already consumed: this permit has already been dispatched (reuse rejected)",
        ))

    # 4. execute -- the ONLY line in this module that can produce an effect.
    started = datetime.now(timezone.utc)
    outcome = executor.execute(tool, arguments)
    ended = datetime.now(timezone.utc)

    # 5. receipt -- built, digested and signed; never fabricated before here.
    receipt = {
        "schema_version": schema_version,
        "type": "ToolReceipt",
        "issuer": signer.identity,
        "issued_at": started.isoformat(),
        "expires_at": (ended + receipt_ttl).isoformat(),
        "run_id": run_id,
        "nonce": f"{nonce}:receipt",
        "key_id": signer.key_id,
        "tool": tool,
        "arguments_digest": actual_digest,
        "effect_digest": canonical.digest_hex(outcome.effect),
        "started_at": started.isoformat(),
        "ended_at": ended.isoformat(),
        "executor": {"id": outcome.executor_id, "role": outcome.executor_role},
        "dispatch_id": dispatch_id,
        "action_digest": permit.get("action_digest"),
    }
    receipt["subject_digest"] = canonical.subject_digest(receipt)
    receipt["signature"] = signer.sign(receipt)
    return ExecutionResult(True, receipt, ())
