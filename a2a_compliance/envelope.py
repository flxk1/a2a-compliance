"""A2A control-message construction + serialization (SPEC §3).

Builds the envelope + verb bodies as concrete `Message` objects and maps them
to/from the on-wire dict shape validated by
`schema/a2a-control-message.schema.json`.

Phase 1: `grounding` and `enforcement` are always None. `to_wire()` emits them
as JSON `null`; `from_wire()` accepts `null` as a first-class value and NEVER
treats it as a failure (SPEC §3.1).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from interfaces.a2a_control import (
    Verb,
    Party,
    Authority,
    Grounding,
    PlaneFinding,
    SteerVerdict,
    Enforcement,
    Message,
)

PROTOCOL = "a2a-compliance/0.1"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_message(
    *,
    from_: Party,
    to: Party,
    verb: Verb,
    body: dict,
    authority: Authority,
    correlates: Optional[str] = None,
    grounding: Optional[Grounding] = None,
    enforcement: Optional[Enforcement] = None,
) -> Message:
    """Construct a well-formed control message with a fresh id + timestamp."""
    return Message(
        id=str(uuid.uuid4()),
        ts=_now(),
        from_=from_,
        to=to,
        verb=verb,
        body=dict(body),
        authority=authority,
        protocol=PROTOCOL,
        correlates=correlates,
        grounding=grounding,
        enforcement=enforcement,
    )


# --- verb body builders (SPEC §3.2 / §3.3) --------------------------------

def query_state_body(include: list[str]) -> dict:
    return {"include": list(include)}


def issue_directive_body(
    instruction: str, kind: str, reason_ref: Optional[str] = None
) -> dict:
    body: dict = {"instruction": instruction, "kind": kind}
    if reason_ref is not None:
        body["reason_ref"] = reason_ref
    return body


def hold_body(
    scope: str,
    reason_ref: Optional[str] = None,
    conditions: Optional[list[str]] = None,
) -> dict:
    body: dict = {"scope": scope}
    if reason_ref is not None:
        body["reason_ref"] = reason_ref
    if conditions is not None:
        body["conditions"] = list(conditions)
    return body


def resume_body(hold_ref: str, note: Optional[str] = None) -> dict:
    body: dict = {"hold_ref": hold_ref}
    if note is not None:
        body["note"] = note
    return body


def halt_body(reason_ref: Optional[str] = None) -> dict:
    body: dict = {"scope": "session", "irreversible": True}
    if reason_ref is not None:
        body["reason_ref"] = reason_ref
    return body


def report_state_body(
    *,
    mandate: Optional[dict] = None,
    trajectory: Optional[list[dict]] = None,
    tools: Optional[dict] = None,
    claims: Optional[list[dict]] = None,
) -> dict:
    """A maker's own account. Always stamped provenance='self-report' — NEVER
    promoted to witnessed/observed (SPEC §3.3)."""
    body: dict = {"provenance": "self-report"}
    if mandate is not None:
        body["mandate"] = mandate
    if trajectory is not None:
        body["trajectory"] = list(trajectory)
    if tools is not None:
        body["tools"] = tools
    if claims is not None:
        body["claims"] = list(claims)
    return body


def ack_body(directive_ref: str, accepted: bool, note: Optional[str] = None) -> dict:
    body: dict = {"directive_ref": directive_ref, "accepted": accepted}
    if note is not None:
        body["note"] = note
    return body


def escalate_body(trigger: str, requested: str, detail: Optional[str] = None) -> dict:
    body: dict = {"trigger": trigger, "requested": requested}
    if detail is not None:
        body["detail"] = detail
    return body


# --- serialization --------------------------------------------------------

def _party_wire(p: Party) -> dict:
    return {"actor": p.actor, "role": p.role}


def _authority_wire(a: Authority) -> dict:
    wire: dict = {"basis": a.basis}
    if a.role is not None:
        wire["role"] = a.role
    if a.oversees is not None:
        wire["oversees"] = a.oversees
    wire["reserved"] = a.reserved
    return wire


def _grounding_wire(g: Optional[Grounding]) -> Optional[dict]:
    if g is None:
        return None
    return {
        "verdict": g.verdict.name,  # schema wants SATISFIED/NOT_SATISFIED/OPEN
        "planes": [
            {"plane": pf.plane, "verdict": pf.verdict.name, "detail": pf.detail}
            for pf in g.planes
        ],
        "criterion_ref": g.criterion_ref,
    }


def _enforcement_wire(e: Optional[Enforcement]) -> Optional[dict]:
    if e is None:
        return None
    return {
        "engine": e.engine,
        "verdict": e.verdict,
        "gate_verdict": e.gate_verdict,
        "audit_id": e.audit_id,
        "advisory": e.advisory,
    }


def to_wire(m: Message) -> dict:
    """Serialize a Message to the schema's on-wire dict. `grounding` and
    `enforcement` serialize to JSON null when absent."""
    return {
        "protocol": m.protocol,
        "id": m.id,
        "correlates": m.correlates,
        "ts": m.ts,
        "from": _party_wire(m.from_),
        "to": _party_wire(m.to),
        "verb": m.verb.value,
        "body": m.body,
        "authority": _authority_wire(m.authority),
        "grounding": _grounding_wire(m.grounding),
        "enforcement": _enforcement_wire(m.enforcement),
    }


def _grounding_from_wire(d: Optional[dict]) -> Optional[Grounding]:
    # A null grounding is a VALID state, never a failure (SPEC §3.1).
    if d is None:
        return None
    return Grounding(
        verdict=SteerVerdict[d["verdict"]],
        planes=[
            PlaneFinding(
                plane=pf["plane"],
                verdict=SteerVerdict[pf["verdict"]],
                detail=pf.get("detail", {}),
            )
            for pf in d.get("planes", [])
        ],
        criterion_ref=d.get("criterion_ref"),
    )


def _enforcement_from_wire(d: Optional[dict]) -> Optional[Enforcement]:
    if d is None:
        return None
    return Enforcement(
        engine=d.get("engine", "rvnd"),
        verdict=d.get("verdict", "permit"),
        gate_verdict=d.get("gate_verdict"),
        audit_id=d.get("audit_id"),
        advisory=d.get("advisory", True),
    )


def from_wire(d: dict) -> Message:
    """Parse an on-wire dict into a Message. Unknown envelope fields are ignored
    (forward-compatibility); null grounding/enforcement parse to None (SPEC §3.1)."""
    return Message(
        id=d["id"],
        ts=d["ts"],
        from_=Party(**d["from"]),
        to=Party(**d["to"]),
        verb=Verb(d["verb"]),
        body=d.get("body", {}),
        authority=Authority(
            basis=d["authority"].get("basis", "role"),
            role=d["authority"].get("role"),
            oversees=d["authority"].get("oversees"),
            reserved=d["authority"].get("reserved", False),
        ),
        protocol=d.get("protocol", PROTOCOL),
        correlates=d.get("correlates"),
        grounding=_grounding_from_wire(d.get("grounding")),
        enforcement=_enforcement_from_wire(d.get("enforcement")),
    )
