"""Compliance-agent send side (SPEC §3.2, §5, §7).

A compliance agent resolves authority role-first (§5.1), bounds a steer by the
maker's declared governance block (§7), and dispatches a control message onto
the A2A channel (the cooperative-poll inbox). In Phase 1 `grounding` and
`enforcement` are always None — the loomground value seam (Phase 2) and the RVND
adapter (Phase 3) are declared-but-inert. No `loomground_*` / `rvnd.*` import is
on this path.

Reserved acts (`halt`; and any reserved kind in a maker's block) are surfaced to
the human and NOT auto-dispatched — in every mode, regardless of enrichment.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from interfaces.a2a_control import Verb, Party, Message, Grounding
from . import envelope as env
from .inbox import FileInbox
from .authority import Roster, Authorization, authorize
from .governance_block import GovernanceBlock, SteerRuling, SteerDecision


@dataclass
class DispatchResult:
    """Outcome of a compliance -> maker send. `dispatched` is False when the act
    was denied by authority, refused by the governance boundary, or surfaced to
    the human as a reserved act (in which case `surfaced_to_human` is True)."""

    dispatched: bool
    authorization: Authorization
    message: Optional[Message] = None
    ruling: Optional[SteerRuling] = None
    surfaced_to_human: bool = False
    denied_reason: Optional[str] = None


@dataclass
class ComplianceAgent:
    """The compliance agent's send side. Implements the `ComplianceChannel`
    seam (interfaces.a2a_control.ComplianceChannel)."""

    session_id: str
    role: str  # a charter compliance role: policy-compliance / grounding / verify
    inbox: FileInbox
    roster: Optional[Roster] = None
    maker_blocks: Optional[dict[str, GovernanceBlock]] = None

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

    def _send(self, msg: Message) -> Message:
        self.inbox.put(msg.to.actor, env.to_wire(msg))
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
        grounding: Optional[Grounding] = None,
    ) -> DispatchResult:
        """Reserved act (§3.2, §5.1): halt is surfaced to the human before
        dispatch in EVERY mode. Without `confirm=True` (the human's approval) it
        is surfaced and NOT dispatched. RVND, when present (Phase 3), would gate
        it additionally; its absence does not lower this bar."""
        auth = self._authorize(Verb.HALT, maker)
        if not auth.allowed:
            return DispatchResult(False, auth, denied_reason=auth.reason)

        if not confirm:
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

    def collect_replies(self) -> list[Message]:
        """Drain this compliance agent's own mailbox (acks / report-state /
        escalate posted back by makers)."""
        return [env.from_wire(w) for w in self.inbox.poll(self.session_id)]
