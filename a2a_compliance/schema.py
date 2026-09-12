"""Schema validation for A2A control messages (SPEC §3).

Validates an on-wire message dict against
`schema/a2a-control-message.schema.json`. `jsonschema` is an ordinary universal
dependency (NOT loomground/external enforcement); its import is still guarded so that a checkout
without it degrades to a minimal structural check rather than crashing the
control path — validation is a check layer, not the load-bearing channel.
"""

from __future__ import annotations

import json
from pathlib import Path

_SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent
    / "schema"
    / "a2a-control-message.schema.json"
)

_REQUIRED_TOP = ("protocol", "id", "ts", "from", "to", "verb", "body", "authority")
_VERBS = {
    "query-state", "issue-directive", "hold", "resume", "halt",
    "report-state", "ack", "escalate",
}


def load_schema() -> dict:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def _structural_check(msg: dict) -> list[str]:
    """Minimal fallback when jsonschema is unavailable."""
    errors: list[str] = []
    for key in _REQUIRED_TOP:
        if key not in msg:
            errors.append(f"missing required field: {key}")
    if msg.get("protocol") != "a2a-compliance/0.1":
        errors.append("protocol must be 'a2a-compliance/0.1'")
    if msg.get("verb") not in _VERBS:
        errors.append(f"unknown verb: {msg.get('verb')!r}")
    auth = msg.get("authority")
    if not isinstance(auth, dict) or auth.get("basis") != "role":
        errors.append("authority.basis must be 'role'")
    # null grounding/enforcement are valid states, never failures.
    return errors


def validate(msg: dict) -> list[str]:
    """Return a list of validation error strings; empty list == valid."""
    try:
        import jsonschema  # type: ignore
    except Exception:
        return _structural_check(msg)

    validator = jsonschema.Draft202012Validator(load_schema())
    return [e.message for e in validator.iter_errors(msg)]


def is_valid(msg: dict) -> bool:
    return not validate(msg)


def assert_valid(msg: dict) -> None:
    errs = validate(msg)
    if errs:
        raise ValueError("invalid A2A control message: " + "; ".join(errs))
