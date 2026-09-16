"""RFC 8785 JSON Canonicalization Scheme (JCS) + SHA-256 subject digest.

Pure, deterministic, no I/O. Object keys sort by UTF-16 code unit sequence
(RFC 8785 3.2.3); numbers format per ECMA-262 Number::toString (RFC 8785
3.2.2.3); strings use the mandatory JSON escapes only (no unnecessary
\\uXXXX escaping of non-ASCII, per RFC 8785 3.2.2.2).
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any


def _utf16_key(s: str) -> tuple:
    """Sort key matching UTF-16 code unit ordering (surrogate pairs for
    astral characters sort by their surrogate code units, not codepoint)."""
    units = []
    for ch in s:
        cp = ord(ch)
        if cp > 0xFFFF:
            cp -= 0x10000
            units.append(0xD800 + (cp >> 10))
            units.append(0xDC00 + (cp & 0x3FF))
        else:
            units.append(cp)
    return tuple(units)


def _encode_string(s: str) -> str:
    # json.dumps with ensure_ascii=False gives the mandatory JSON escapes
    # (", \\, control chars) and leaves other Unicode untouched, which is
    # exactly RFC 8785's string requirement.
    return json.dumps(s, ensure_ascii=False)


def _number_to_es_string(value: float) -> str:
    """ECMA-262 Number::toString applied to a JSON number (RFC 8785 3.2.2.3)."""
    if math.isnan(value) or math.isinf(value):
        raise ValueError("NaN/Infinity are not valid JSON numbers")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    value = abs(value)

    # Shortest round-trip decimal digits + exponent, via Python's own
    # shortest-round-trip repr (same mathematical digit string ECMAScript's
    # algorithm would produce; only the *formatting* rules differ below).
    text = repr(value)
    if "e" in text or "E" in text:
        mantissa, _, exp_text = text.partition("e") if "e" in text else text.partition("E")
        exp10 = int(exp_text)
    else:
        mantissa, exp10 = text, 0
    if "." in mantissa:
        int_part, frac_part = mantissa.split(".")
    else:
        int_part, frac_part = mantissa, ""
    digits = (int_part + frac_part).lstrip("0")
    # position of the decimal point relative to `digits`, before stripping
    point_pos = len(int_part) - (len(int_part + frac_part) - len(digits))
    if not digits:
        return "0"
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    n = point_pos + exp10

    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        exp = n - 1
        exp_sign = "+" if exp >= 0 else "-"
        mantissa_str = digits[0] if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mantissa_str}e{exp_sign}{abs(exp)}"
    return sign + body


def _canon(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _number_to_es_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_canon(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: _utf16_key(kv[0]))
        return "{" + ",".join(f"{_encode_string(k)}:{_canon(v)}" for k, v in items) + "}"
    raise TypeError(f"not JSON-serialisable: {type(value)!r}")


def canonicalize(value: Any) -> str:
    """Return the RFC 8785 canonical JSON text for `value`."""
    return _canon(value)


def canonical_bytes(value: Any) -> bytes:
    return canonicalize(value).encode("utf-8")


def digest_hex(value: Any) -> str:
    """SHA-256 hex digest of the canonical bytes."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def subject(obj: dict) -> dict:
    """The signed/digested portion of a wire object: itself with `signature`
    and `subject_digest` removed. Both `subject_digest` (below) and E1's
    `wire.signing` DSSE construction call this SAME function, so what gets
    hashed and what gets signed can never silently diverge."""
    return {k: v for k, v in obj.items() if k not in ("signature", "subject_digest")}


def subject_digest(obj: dict) -> str:
    """RFC 8785 digest over an object with its `signature` field removed —
    this is the wire `subject_digest`. `subject_digest` itself is also
    excluded from its own input: a digest cannot include itself (same
    non-circularity every signing scheme applies to its own digest/signature
    fields); the plan's "object minus the signature field" is read that way,
    since a literal minus-only-signature reading is self-referential and
    cannot be satisfied by any value."""
    return digest_hex(subject(obj))
