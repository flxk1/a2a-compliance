"""Enforcement wire contracts: JSON Schemas, RFC 8785 canonical digest, a
pure fail-closed verifier (E0), DSSE/Ed25519 signature verification,
trust-role bindings, revocation and receipt-chain linkage (E1), a verified
admission decision plus permit issuance (E2, `admission.py`), and a mediated
executor that consumes an admitted permit's nonce and produces a signed
ToolReceipt (E3, `executor.py`). No host effect at any point: the real
effect lives only behind the `ExecutorPort` a host injects into
`consume_and_execute` -- see `examples/subprocess_adapter.py` for the
conformance adapter, which is not part of this package.

`canonical` is stdlib-only and imported eagerly, so `a2a_compliance.wire.canonical`
(and anything that only needs it, e.g. `team.py`'s action_digest) is importable
without `jsonschema`/`referencing`/`cryptography` installed. `schema_registry` and
`verification` need `jsonschema`; `signing` needs `cryptography` (only inside its
functions, see that module's docstring). All are loaded lazily (PEP 562 `__getattr__`)
so merely importing `a2a_compliance.wire` -- or `a2a_compliance.team`, which imports
`.wire.canonical` at module level -- never requires any of them. They import fine,
and eagerly, the moment anything actually touches one of the `_LAZY` names below;
`verify()` itself only reaches into `signing` (and so only then requires
`cryptography`) when a caller passes a `trust_store`.

The public `verify` function is exported from the `verification` submodule (not a
submodule named `verify`, to avoid Python's import system binding
`wire.__dict__["verify"]` to a same-named submodule as a side effect of anyone
importing it directly).
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
    "TrustBinding",
    "TrustStore",
    "InMemoryTrustStore",
    "RevocationStore",
    "InMemoryRevocationStore",
    "ChainVerificationResult",
    "verify_chain",
    "DSSE_PAYLOAD_TYPE",
    "generate_dev_keypair",
    "dev_sign_subject",
    "AdmissionDecision",
    "AdmissionResult",
    "admit",
    "ApproverAuthority",
    "InMemoryApproverAuthority",
    "Issuer",
    "dev_issuer",
    "PermitIssueResult",
    "issue_permit",
    "ExecutionOutcome",
    "ExecutorPort",
    "ExecutionResult",
    "bind_constraints",
    "consume_and_execute",
]

_LAZY = {
    "WIRE_TYPES": ("schema_registry", "WIRE_TYPES"),
    "load_schema": ("schema_registry", "load_schema"),
    "validator_for": ("schema_registry", "validator_for"),
    "InMemoryNonceStore": ("verification", "InMemoryNonceStore"),
    "NonceStore": ("verification", "NonceStore"),
    "VerificationResult": ("verification", "VerificationResult"),
    "verify": ("verification", "verify"),
    "TrustBinding": ("trust", "TrustBinding"),
    "TrustStore": ("trust", "TrustStore"),
    "InMemoryTrustStore": ("trust", "InMemoryTrustStore"),
    "RevocationStore": ("trust", "RevocationStore"),
    "InMemoryRevocationStore": ("trust", "InMemoryRevocationStore"),
    "ChainVerificationResult": ("chain", "ChainVerificationResult"),
    "verify_chain": ("chain", "verify_chain"),
    "DSSE_PAYLOAD_TYPE": ("signing", "DSSE_PAYLOAD_TYPE"),
    "generate_dev_keypair": ("signing", "generate_dev_keypair"),
    "dev_sign_subject": ("signing", "dev_sign_subject"),
    "AdmissionDecision": ("admission", "AdmissionDecision"),
    "AdmissionResult": ("admission", "AdmissionResult"),
    "admit": ("admission", "admit"),
    "ApproverAuthority": ("admission", "ApproverAuthority"),
    "InMemoryApproverAuthority": ("admission", "InMemoryApproverAuthority"),
    "Issuer": ("admission", "Issuer"),
    "dev_issuer": ("admission", "dev_issuer"),
    "PermitIssueResult": ("admission", "PermitIssueResult"),
    "issue_permit": ("admission", "issue_permit"),
    "ExecutionOutcome": ("executor", "ExecutionOutcome"),
    "ExecutorPort": ("executor", "ExecutorPort"),
    "ExecutionResult": ("executor", "ExecutionResult"),
    "bind_constraints": ("executor", "bind_constraints"),
    "consume_and_execute": ("executor", "consume_and_execute"),
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
