"""E0 enforcement wire contracts: JSON Schemas, RFC 8785 canonical digest and a
pure, fail-closed verifier. No signature verification (E1) and no host effect.

`canonical` is stdlib-only and imported eagerly, so `a2a_compliance.wire.canonical`
(and anything that only needs it, e.g. `team.py`'s action_digest) is importable
without `jsonschema`/`referencing` installed. `schema_registry` and `verify` need
`jsonschema`; they are loaded lazily (PEP 562 `__getattr__`) so merely importing
`a2a_compliance.wire` — or `a2a_compliance.team`, which imports `.wire.canonical`
at module level — never requires them. They still import fine, and eagerly, the
moment anything actually touches `WIRE_TYPES`/`load_schema`/`validator_for`/
`InMemoryNonceStore`/`NonceStore`/`VerificationResult`/`verify`.
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
    "InMemoryNonceStore": ("verify", "InMemoryNonceStore"),
    "NonceStore": ("verify", "NonceStore"),
    "VerificationResult": ("verify", "VerificationResult"),
    "verify": ("verify", "verify"),
}


def __getattr__(name: str):
    try:
        module_name, _ = _LAZY[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    module = import_module(f".{module_name}", __name__)
    # `verify.py`'s own `verify` function shares its name with the submodule
    # itself; importing that submodule for ANY of its lazy names makes
    # Python's import system stash the MODULE under `wire.verify` as a side
    # effect, pre-empting our own caching for that one name. Resolve every
    # lazy name sourced from this module in one pass so that side effect is
    # always overwritten immediately, regardless of which name triggered it.
    for lazy_name, (owner, attr_name) in _LAZY.items():
        if owner == module_name:
            globals()[lazy_name] = getattr(module, attr_name)
    return globals()[name]


def __dir__():
    return sorted(set(globals()) | set(_LAZY))
