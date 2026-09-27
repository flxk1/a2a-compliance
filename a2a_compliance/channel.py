"""Compliance-agent send side (SPEC §3.2, §5, §7).

A compliance agent resolves authority role-first (§5.1), bounds a steer by the
maker's declared governance block (§7), and dispatches a control message onto
the A2A channel (the cooperative-poll inbox). In Phase 1 `grounding` and
`enforcement` are always None — the loomground value seam (Phase 2) and the
external-enforcement adapter (Phase 3) are declared-but-inert. No enrichment
provider is imported on this path.

Reserved acts (`halt`; and any reserved kind in a maker's block) are surfaced to
the human and NOT auto-dispatched — in every mode, regardless of enrichment.

--- Authenticated control channel + gated halt (OWASP ASI07; AI Act Art. 14(4)) --

AUTHENTICATED mode is entered by configuring `trust_store` on this agent (the
same TrustStore a `ControlParticipant` verifies against). In that mode:

- every outbound envelope is signed via an injected `signer` (an
  `Issuer`-shaped object: `key_id`/`identity`/`sign`, the same shape
  `wire/admission.py` already uses — this package never embeds or fabricates a
  production key; `wire.admission.dev_issuer` is the TEST-ONLY convenience);
  signing itself goes through `wire/signing.py` exclusively.
- `halt()` additionally requires a verified `HumanApprovalReceipt` bound to
  this exact halt (via `envelope.halt_digest`) and approved by a human
  identity distinct from the sender. `confirm=True` alone NEVER dispatches a
  halt in this mode — it is meaningless without a receipt.

In BARE mode (`trust_store` is None, the Phase-1 default) outbound envelopes
stay unsigned and `halt()` keeps the original advisory `confirm=True` human
gate — documented here as advisory-only, never mistaken for a cryptographic
approval.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from interfaces.a2a_control import Verb, Party, Message, Grounding
from . import envelope as env
from .inbox import FileInbox
from .authority import HUMAN_ROLE, Roster, Authorization, authorize
from .governance_block import GovernanceBlock, SteerRuling, SteerDecision
from .nonce_store import FileNonceStore, safe_component

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime
    from .wire.admission import Issuer
    from .wire.trust import RevocationStore, TrustStore
    from .wire.verification import NonceStore

# The scopes a `HumanApprovalReceipt` may carry for a halt approval (schema:
# human-approval-receipt.schema.json's `scope` enum). Any other value is
# rejected explicitly here too (defense in depth alongside schema
# validation) -- FIX 2(b): "unknown scope rejects".
HALT_APPROVAL_SCOPES = frozenset({"next-action", "session"})

# Sentinel `nonce` value (never a real receipt nonce -- receipts are
# schema-shaped strings from a signer, never this literal) used to mark,
# per run_id, that a 'next-action'-scoped halt approval has already been
# spent in this run. See `_verify_halt_approval`'s scope-RULE check.
_NEXT_ACTION_SCOPE_MARKER = "__halt:next-action-scope-used__"


@dataclass
class DispatchResult:
    """Outcome of a compliance -> maker send. `dispatched` is False when the act
    was denied by authority, refused by the governance boundary, or surfaced to
    the human as a reserved act (in which case `surfaced_to_human` is True).

    `grounding_result` (Phase 2) carries the value-graph derivation when the send
    came from `ground_and_steer`; None otherwise (a bare Phase-1 send)."""

    dispatched: bool
    authorization: Authorization
    message: Optional[Message] = None
    ruling: Optional[SteerRuling] = None
    surfaced_to_human: bool = False
    denied_reason: Optional[str] = None
    grounding_result: Optional[object] = None


@dataclass
class ComplianceAgent:
    """The compliance agent's send side. Implements the `ComplianceChannel`
    seam (interfaces.a2a_control.ComplianceChannel)."""

    session_id: str
    role: str  # a charter compliance role: policy-compliance / grounding / verify
    inbox: FileInbox
    roster: Optional[Roster] = None
    maker_blocks: Optional[dict[str, GovernanceBlock]] = None
    trust_store: Optional["TrustStore"] = None
    revocation_store: Optional["RevocationStore"] = None
    nonce_store: Optional["NonceStore"] = None
    signer: Optional["Issuer"] = None

    def __post_init__(self) -> None:
        """FIX 2(c): AUTHENTICATED mode must never silently skip single-use
        enforcement on a halt approval receipt just because a caller did not
        inject its own `nonce_store` -- default to a durable `FileNonceStore`
        scoped under this agent's own inbox root/session id (never `None`),
        exactly the same durable-default posture `ControlParticipant` takes
        (see `participant.py`'s `__post_init__` and `nonce_store.py`)."""
        if self.trust_store is not None and self.nonce_store is None:
            # See `participant.py`'s identical guard: fall back to a
            # process-local temp directory when `inbox` is a non-durable
            # duck-typed stand-in without a `.root`, rather than crash.
            root_hint = getattr(self.inbox, "root", None)
            if root_hint is not None:
                default_root = Path(root_hint) / ".nonces" / safe_component(self.session_id)
            else:
                import tempfile

                default_root = Path(tempfile.mkdtemp(prefix="a2a-nonce-"))
            self.nonce_store = FileNonceStore(default_root)

    def _me(self) -> Party:
        return Party(actor=self.session_id, role=self.role)

    def _maker_party(self, maker: str) -> Party:
        return Party(actor=maker, role="maker")

    def _authorize(self, verb: Verb, maker: str) -> Authorization:
        return authorize(
            from_role=self.role, verb=verb, maker_id=maker, roster=self.roster
        )

    def _block_for(self, maker: str) -> Optional[GovernanceBlock]:
        return (self.maker_blocks or {}).get(maker)

    @property
    def authenticated_mode(self) -> bool:
        """True when a `TrustStore` is configured — AUTHENTICATED mode."""
        return self.trust_store is not None

    def _send(self, msg: Message) -> Message:
        wire = env.to_wire(msg)
        if self.authenticated_mode and self.signer is not None:
            wire = env.stamp_and_sign(
                wire, key_id=self.signer.key_id, sign=self.signer.sign,
            )
        self.inbox.put(msg.to.actor, wire)
        return msg

    # --- verbs ---------------------------------------------------------------

    def query_state(self, maker: str, include: list[str]) -> DispatchResult:
        auth = self._authorize(Verb.QUERY_STATE, maker)
        if not auth.allowed:
            return DispatchResult(False, auth, denied_reason=auth.reason)
        msg = env.new_message(
            from_=self._me(),
            to=self._maker_party(maker),
            verb=Verb.QUERY_STATE,
            body=env.query_state_body(include),
            authority=auth.to_block(),
        )
        return DispatchResult(True, auth, message=self._send(msg))

    def issue_directive(
        self,
        maker: str,
        instruction: str,
        kind: str,
        *,
        target_kind: Optional[str] = None,
        reason_ref: Optional[str] = None,
        grounding: Optional[Grounding] = None,  # Phase 2 seam; None in Phase 1
    ) -> DispatchResult:
        """Steer a maker. `kind` is the steer type (correct/constrain/redirect);
        `target_kind` (optional) is the maker governance-block action the
        directive would push the maker toward — checked against the block (§7)."""
        auth = self._authorize(Verb.ISSUE_DIRECTIVE, maker)
        if not auth.allowed:
            return DispatchResult(False, auth, denied_reason=auth.reason)

        ruling: Optional[SteerRuling] = None
        block = self._block_for(maker)
        if block is not None and target_kind is not None:
            ruling = block.rule(target_kind)
            if ruling.decision is SteerDecision.REFUSE:
                return DispatchResult(
                    False, auth, ruling=ruling, denied_reason=ruling.reason
                )
            if ruling.decision is SteerDecision.ROUTE_HUMAN:
                return DispatchResult(
                    False, auth, ruling=ruling, surfaced_to_human=True,
                    denied_reason=ruling.reason,
                )

        msg = env.new_message(
            from_=self._me(),
            to=self._maker_party(maker),
            verb=Verb.ISSUE_DIRECTIVE,
            body=env.issue_directive_body(instruction, kind, reason_ref),
            authority=auth.to_block(),
            grounding=grounding,  # None in Phase 1
        )
        return DispatchResult(True, auth, message=self._send(msg), ruling=ruling)

    def hold(
        self,
        maker: str,
        scope: str = "next-action",
        *,
        reason_ref: Optional[str] = None,
        conditions: Optional[list[str]] = None,
        grounding: Optional[Grounding] = None,
    ) -> DispatchResult:
        auth = self._authorize(Verb.HOLD, maker)
        if not auth.allowed:
            return DispatchResult(False, auth, denied_reason=auth.reason)
        msg = env.new_message(
            from_=self._me(),
            to=self._maker_party(maker),
            verb=Verb.HOLD,
            body=env.hold_body(scope, reason_ref, conditions),
            authority=auth.to_block(),
            grounding=grounding,
        )
        return DispatchResult(True, auth, message=self._send(msg))

    def resume(self, maker: str, hold_ref: str, note: Optional[str] = None) -> DispatchResult:
        auth = self._authorize(Verb.RESUME, maker)
        if not auth.allowed:
            return DispatchResult(False, auth, denied_reason=auth.reason)
        msg = env.new_message(
            from_=self._me(),
            to=self._maker_party(maker),
            verb=Verb.RESUME,
            body=env.resume_body(hold_ref, note),
            authority=auth.to_block(),
        )
        return DispatchResult(True, auth, message=self._send(msg))

    def halt(
        self,
        maker: str,
        *,
        reason_ref: Optional[str] = None,
        confirm: bool = False,
        approval: Optional[dict] = None,
        grounding: Optional[Grounding] = None,
        now: Optional[datetime] = None,
    ) -> DispatchResult:
        """Reserved act (§3.2, §5.1): halt is surfaced to the human before
        dispatch in EVERY mode. External enforcement, when present (Phase 3),
        would gate it additionally; its absence does not lower this bar.

        AUTHENTICATED mode (`trust_store` configured): `confirm=True` alone
        NEVER dispatches. `approval` must be a `HumanApprovalReceipt` (wire
        dict) that (a) VERIFIES via `wire.verification.verify` against this
        agent's `trust_store`/`revocation_store`/`nonce_store` — reused
        read-only, never reimplemented; (b) is bound to this exact halt via
        `permitted_action_digest == envelope.halt_digest(...)`, so a receipt
        approving a different halt (or a different maker) can never be
        replayed onto this one; and (c) carries an `approver` whose role is
        `authority.HUMAN_ROLE` and whose id differs from this agent's own
        `session_id` and from `maker` — an approver cannot be the sender, and
        cannot be the maker being halted. Any failure surfaces to the human
        and does NOT dispatch.

        BARE mode (no `trust_store`): the original advisory gate — `confirm
        =True` (the human's approval, asserted out of band) dispatches; there
        is no cryptographic binding here, which is exactly why AUTHENTICATED
        mode exists."""
        auth = self._authorize(Verb.HALT, maker)
        if not auth.allowed:
            return DispatchResult(False, auth, denied_reason=auth.reason)

        if self.authenticated_mode:
            digest = env.halt_digest(self.session_id, maker, reason_ref)
            reason = self._verify_halt_approval(approval, digest, maker, now=now)
            if reason is not None:
                return DispatchResult(
                    False, auth, surfaced_to_human=True, denied_reason=reason,
                )
        elif not confirm:
            return DispatchResult(
                False, auth, surfaced_to_human=True,
                denied_reason="halt is a reserved act — surfaced to the human; "
                "re-issue with confirm=True after human approval",
            )

        msg = env.new_message(
            from_=self._me(),
            to=self._maker_party(maker),
            verb=Verb.HALT,
            body=env.halt_body(reason_ref),
            authority=auth.to_block(),
            grounding=grounding,
        )
        return DispatchResult(True, auth, message=self._send(msg), surfaced_to_human=True)

    def _verify_halt_approval(
        self, approval: Optional[dict], digest: str, maker: str, *, now: Optional[datetime],
    ) -> Optional[str]:
        """Returns None when `approval` is a verified, digest-bound,
        single-use, in-scope receipt from a distinct authorized human;
        otherwise the denial reason. AUTHENTICATED-mode-only helper.

        Reuses `wire.verification.verify_human_approval` (E1, read-only)
        for WHO approved: it checks the SIGNING KEY's bound role/identity
        (deployment config), never the receipt's own self-declared
        `approver.id`/`approver.role` fields taken at face value -- closing
        the exact gap the recorded `exploit.py` used (a sender's own agent
        key, authorized for `HumanApprovalReceipt` but bound to no human
        role/identity, self-declaring a human approver).

        Four checks layer on top, none of them reimplementing
        `verify_human_approval`'s own signature/schema/trust/identity work:
        (1) digest binding -- unchanged; (2) the bound approver identity
        must also differ from `maker` (verify_human_approval only checks it
        differs from the SENDER); (3) the scope RULE itself -- `scope` must
        be a recognized value (defense in depth alongside the schema's own
        enum, which currently mirrors `HALT_APPROVAL_SCOPES` exactly) AND,
        when it is `'next-action'`, it authorises only the SINGLE next halt
        for this `run_id` -- a second, otherwise-fully-valid receipt with
        its own fresh `(run_id, nonce)` and its own digest cannot approve a
        second halt in the same run under `'next-action'` scope (only
        `'session'` scope may); (4) single-use -- FIX 2(b): the receipt's
        own `(run_id, nonce)` is CONSUMED (atomic compare-and-set) only
        after every other check has passed, so a forged/tampered/out-of-scope
        receipt can never burn a legitimate nonce, and a legitimate receipt
        can never approve a second halt."""
        if approval is None:
            return (
                "halt requires a verified HumanApprovalReceipt in authenticated "
                "mode; confirm=True alone does not dispatch"
            )

        from .wire.verification import verify_human_approval  # local: needs jsonschema/cryptography

        result = verify_human_approval(
            approval, trust_store=self.trust_store, revocation_store=self.revocation_store,
            now=now, sender_identity=self.session_id, human_role=HUMAN_ROLE,
        )
        if not result.ok:
            return "halt approval receipt failed verification: " + "; ".join(result.errors)

        if approval.get("permitted_action_digest") != digest:
            return "halt approval is not bound to this halt's digest"

        if result.approver_identity == maker:
            return "halt approver must be a human identity distinct from the sender/maker"

        scope = approval.get("scope")
        if scope not in HALT_APPROVAL_SCOPES:
            return f"halt approval scope {scope!r} is not a recognized scope"

        run_id, nonce = approval.get("run_id"), approval.get("nonce")
        if not run_id or not nonce:
            return "halt approval receipt is missing run_id/nonce needed for single-use enforcement"

        if self.nonce_store is None:
            # __post_init__ defaults this in authenticated mode; reject
            # rather than silently skip single-use enforcement if a caller
            # ever mutates it back to None (fail closed, FIX 2c posture).
            return "halt approval cannot be enforced single-use without a nonce store"

        if not self.nonce_store.consume(run_id, nonce):
            # The SAME receipt presented twice: this per-receipt single-use
            # check runs first, so an identical replay is reported this way
            # (unchanged), never as the distinct scope-rule denial below.
            return "halt approval receipt has already been used (single-use)"

        if scope == "next-action" and self.nonce_store.seen(run_id, _NEXT_ACTION_SCOPE_MARKER):
            # The scope RULE itself (not merely the enum-membership check
            # above): 'next-action' authorises exactly ONE halt for this
            # run_id, ever -- distinct from the per-receipt single-use
            # nonce just consumed, which only stops the SAME receipt being
            # replayed. A second, independently signed, otherwise fully
            # valid 'next-action' receipt (its own fresh (run_id, nonce)
            # and its own digest, for a DIFFERENT halt) must still be
            # refused here; only 'session' scope may authorise more than
            # one halt per run.
            return "halt approval scope 'next-action' already used for a prior halt in this run"

        if scope == "next-action":
            # Recorded only now that every other check (including this
            # receipt's own single-use nonce, just consumed above) has
            # passed, so a rejected/forged receipt never burns this run's
            # next-action allowance.
            self.nonce_store.record(run_id, _NEXT_ACTION_SCOPE_MARKER)

        return None

    def collect_replies(self) -> list[Message]:
        """Drain this compliance agent's own mailbox (acks / report-state /
        escalate posted back by makers)."""
        return [env.from_wire(w) for w in self.inbox.poll(self.session_id)]

    # --- Phase 2: value-grounded steer (SPEC §4) -----------------------------

    def ground_and_steer(
        self,
        maker: str,
        context,
        *,
        target_kind: Optional[str] = None,
        planes: Optional[tuple[str, ...]] = None,
    ) -> DispatchResult:
        """Derive a steer/hold/escalate from the loomground value graph and dispatch
        the mapped verb, attaching the grounded `Grounding` block to the message.

        Bare mode (no plane present, or all disabled): `ground()` returns
        `grounding=None` and a role-advisory recommendation — identical to a Phase-1
        send. A plane present sharpens the criterion; each dimension degrades
        independently. Mapping: prohibition/gamed -> hold; escalation ceiling ->
        route-human (reserved, not dispatched); mandate/norm -> steer; OPEN -> route
        to human. The grounding module is imported lazily so the bare import path
        stays loomground-free."""
        from . import grounding as G

        result = G.ground(context, planes=planes if planes is not None else G.ALL_PLANES)
        block = result.grounding  # envelope grounding block (None in bare mode)

        if result.recommended_action == G.ACTION_HOLD:
            disp = self.hold(
                maker, "next-action", reason_ref="grounded", grounding=block
            )
            disp.grounding_result = result
            return disp

        if result.recommended_action == G.ACTION_STEER:
            disp = self.issue_directive(
                maker, result.reason, "constrain",
                target_kind=target_kind, reason_ref="grounded", grounding=block,
            )
            disp.grounding_result = result
            return disp

        if result.recommended_action == G.ACTION_ROUTE_HUMAN:
            # Reserved: an over-ceiling / unassessed finding surfaces to the human and
            # is NOT auto-dispatched (SPEC §4.1, §5.1 reserved-act posture).
            auth = self._authorize(Verb.ISSUE_DIRECTIVE, maker)
            return DispatchResult(
                False, auth, surfaced_to_human=True,
                denied_reason=f"grounded finding routes to the human: {result.reason}",
                grounding_result=result,
            )

        # no-steer: the maker is within values; nothing is dispatched.
        auth = self._authorize(Verb.QUERY_STATE, maker)
        return DispatchResult(
            False, auth, denied_reason=None, grounding_result=result,
        )
