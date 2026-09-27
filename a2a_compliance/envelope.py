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
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

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
DEFAULT_TTL_SECONDS = 300


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
    `enforcement` serialize to JSON null when absent. `nonce`/`expires_at`/
    `key_id`/`signature` are omitted (never emitted as null) when the message
    was never stamped for the authenticated channel -- an unsigned envelope
    stays byte-for-byte the bare-mode shape."""
    wire: dict = {
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
    if m.nonce is not None:
        wire["nonce"] = m.nonce
    if m.expires_at is not None:
        wire["expires_at"] = m.expires_at
    if m.key_id is not None:
        wire["key_id"] = m.key_id
    if m.signature is not None:
        wire["signature"] = m.signature
    return wire


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
        engine=d.get("engine", "external"),
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
        nonce=d.get("nonce"),
        expires_at=d.get("expires_at"),
        key_id=d.get("key_id"),
        signature=d.get("signature"),
    )


# --- authenticated-channel helpers (OWASP ASI07 hardening) ----------------
#
# Signing/verification themselves are NEVER duplicated here: signing goes
# through `wire.signing` (Ed25519 over the RFC 8785 canonical/PAE bytes),
# imported lazily below so the bare/module-import path never requires
# `cryptography`. This module only stamps the nonce/expiry an authenticated
# sender needs and hands the exact bytes to an injected signer.

def new_nonce() -> str:
    """A fresh single-use token for one outbound envelope."""
    return uuid.uuid4().hex


def stamp_and_sign(
    wire: dict,
    *,
    key_id: str,
    sign: Callable[[dict], str],
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    nonce: Optional[str] = None,
    now: Optional[datetime] = None,
) -> dict:
    """Return a COPY of `wire` stamped with `nonce`/`expires_at`/`key_id` and
    signed by the injected `sign` callable (an `Issuer`-style signer; this
    package itself never holds or fabricates a production key -- see
    `wire/admission.py`'s `Issuer`/`dev_issuer` for the same pattern).

    `sign` receives the envelope dict with `nonce`/`expires_at`/`key_id`
    already set and must return the base64 Ed25519 signature over its DSSE
    PAE (`wire.signing.pae_bytes`/`dev_sign_subject` do this); the signature
    itself is computed over the canonical *subject* (signature/subject_digest
    excluded), so binding a `nonce`/`expires_at` here into the signed dict
    ties them into what gets signed -- a tampered nonce or expiry invalidates
    the signature, it cannot be swapped in afterwards."""
    reference = now if now is not None else datetime.now(timezone.utc)
    signed = dict(wire)
    signed["nonce"] = nonce if nonce is not None else new_nonce()
    signed["expires_at"] = (reference + timedelta(seconds=ttl_seconds)).isoformat()
    signed["key_id"] = key_id
    signed.pop("signature", None)
    signed["signature"] = sign(signed)
    return signed


def halt_digest(compliance_actor: str, maker: str, reason_ref: Optional[str] = None) -> str:
    """The digest a `HumanApprovalReceipt.permitted_action_digest` must bind
    to in order to approve one exact halt: RFC 8785 canonical digest over the
    halt's identifying fields (never the whole envelope, so a fresh envelope
    id/timestamp/nonce per halt attempt still binds to the same approval).
    Reuses `wire.canonical` (read-only) -- no digest scheme is reinvented
    here."""
    from .wire import canonical

    subject = {
        "verb": Verb.HALT.value,
        "from": compliance_actor,
        "to": maker,
        "reason_ref": reason_ref,
    }
    return canonical.digest_hex(subject)
