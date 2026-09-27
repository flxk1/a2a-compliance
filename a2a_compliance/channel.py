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
from typing import TYPE_CHECKING, Optional

from interfaces.a2a_control import Verb, Party, Message, Grounding
from . import envelope as env
from .inbox import FileInbox
from .authority import HUMAN_ROLE, Roster, Authorization, authorize
from .governance_block import GovernanceBlock, SteerRuling, SteerDecision

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime
    from .wire.admission import Issuer
    from .wire.trust import RevocationStore, TrustStore
    from .wire.verification import NonceStore


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
        """Returns None when `approval` is a verified, digest-bound receipt
        from a distinct authorized human; otherwise the denial reason.
        AUTHENTICATED-mode-only helper — reuses the public `wire.verification.
        verify` (E1) read-only rather than reimplementing signature/expiry/
        replay/trust checks."""
        if approval is None:
            return (
                "halt requires a verified HumanApprovalReceipt in authenticated "
                "mode; confirm=True alone does not dispatch"
            )

        from .wire.verification import verify  # local: needs jsonschema/cryptography

        result = verify(
            approval, "HumanApprovalReceipt",
            trust_store=self.trust_store, revocation_store=self.revocation_store,
            nonce_store=self.nonce_store, now=now,
        )
        if not result.ok:
            return "halt approval receipt failed verification: " + "; ".join(result.errors)

        if approval.get("permitted_action_digest") != digest:
            return "halt approval is not bound to this halt's digest"

        approver = approval.get("approver") or {}
        approver_id = approver.get("id")
        approver_role = approver.get("role")
        if approver_role != HUMAN_ROLE:
            return (
                f"halt approver role {approver_role!r} is not an authorized "
                f"human identity (must be {HUMAN_ROLE!r})"
            )
        if not approver_id or approver_id in (self.session_id, maker):
            return "halt approver must be a human identity distinct from the sender/maker"

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
