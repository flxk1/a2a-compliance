"""E0 enforcement wire contracts: JSON Schemas, RFC 8785 canonical digest and a
pure, fail-closed verifier. No signature verification (E1) and no host effect.

`canonical` is stdlib-only and imported eagerly, so `a2a_compliance.wire.canonical`
(and anything that only needs it, e.g. `team.py`'s action_digest) is importable
without `jsonschema`/`referencing` installed. `schema_registry` and `verification`
need `jsonschema`; they are loaded lazily (PEP 562 `__getattr__`) so merely importing
`a2a_compliance.wire` — or `a2a_compliance.team`, which imports `.wire.canonical`
at module level — never requires them. They still import fine, and eagerly, the
moment anything actually touches `WIRE_TYPES`/`load_schema`/`validator_for`/
`InMemoryNonceStore`/`NonceStore`/`VerificationResult`/`verify`.

The public `verify` function is exported from the `verification` submodule
(not `verify`, to avoid Python's import system binding `wire.__dict__["verify"]`
to a same-named submodule as a side effect of anyone importing it directly).
"""

from importlib import import_module

from . import canonical

__all__ = [
    "canonical",
    "WIRE_TYPES",
    "load_schema",
    "validator_for",
    "InMemoryNonceStore",
    "NonceStore",
    "VerificationResult",
    "verify",
]

_LAZY = {
    "WIRE_TYPES": ("schema_registry", "WIRE_TYPES"),
    "load_schema": ("schema_registry", "load_schema"),
    "validator_for": ("schema_registry", "validator_for"),
    "InMemoryNonceStore": ("verification", "InMemoryNonceStore"),
    "NonceStore": ("verification", "NonceStore"),
    "VerificationResult": ("verification", "VerificationResult"),
    "verify": ("verification", "verify"),
}


def __getattr__(name: str):
    try:
        module_name, attr_name = _LAZY[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    module = import_module(f".{module_name}", __name__)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(_LAZY))
