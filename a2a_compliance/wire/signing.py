"""DSSE/Ed25519 signature construction and verification (E1).

This is the ONLY module in this package that imports `cryptography`, and it
does so function-local (never at module import time), so that neither
`import a2a_compliance.wire.signing` nor anything upstream of it requires
`cryptography` to be installed -- only actually CALLING one of these
functions does. `cryptography` is an OPTIONAL dependency (pyproject
`crypto`/`dev` extras); the bare install stays importable without it.

DSSE (github.com/secure-systems-lab/dsse) Pre-Authentication Encoding:

    PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body

signed with Ed25519 over `body` = the RFC 8785 canonical bytes of the
object's *subject* -- the same bytes `wire.canonical.subject_digest` hashes:
the object with `signature`/`subject_digest` removed. Signing the full
canonical subject, not just its digest, ties the signature to the actual
content rather than to one digest algorithm's output; `subject_digest` (an
independent sha256 over the same bytes) stays a fast, digest-only equality
check performed earlier in `wire.verification.verify`.

Design decision surfaced for human confirmation: `DSSE_PAYLOAD_TYPE` below is
a fixed string for this package's wire objects. A future cross-repo consumer
(e.g. evidence-emitter) MUST use the identical payload type string or
signatures will not interoperate -- that alignment is explicitly a follow-on,
not decided here.
"""

from __future__ import annotations

import base64
import binascii

from . import canonical

DSSE_PAYLOAD_TYPE = "application/vnd.a2a-compliance.subject+json"


def _pae(payload_type: str, payload: bytes) -> bytes:
    pt = payload_type.encode("utf-8")
    return (
        b"DSSEv1 " + str(len(pt)).encode("ascii") + b" " + pt
        + b" " + str(len(payload)).encode("ascii") + b" " + payload
    )


def pae_bytes(obj: dict) -> bytes:
    """The exact bytes an Ed25519 signature over `obj` is computed over.
    Uses `canonical.subject` -- the same subject-extraction `subject_digest`
    hashes -- so signing and digesting can never see a different view of
    the same object."""
    return _pae(DSSE_PAYLOAD_TYPE, canonical.canonical_bytes(canonical.subject(obj)))


def generate_dev_keypair() -> tuple[bytes, bytes]:
    """TEST-ONLY. Generates an ephemeral Ed25519 keypair and returns
    `(private_key_bytes, public_key_bytes)`, both raw 32-byte encodings.
    a2a-compliance core never accepts or requires a production signing key
    (fixed trust boundary) -- this function exists for conformance vectors
    and test fixtures only. Never call it outside tests/vector generation."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, public_bytes


def dev_sign_subject(obj: dict, private_key_bytes: bytes) -> str:
    """TEST-ONLY dev signer. Signs `pae_bytes(obj)` with the given raw
    32-byte Ed25519 private key and returns the base64 signature for the
    wire `signature` field. Never a production signer; the core package
    only VERIFIES signatures, it never produces one outside test vectors."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    signature = private_key.sign(pae_bytes(obj))
    return base64.b64encode(signature).decode("ascii")


def verify_signature(obj: dict, public_key_bytes: bytes) -> list[str]:
    """Verify `obj["signature"]` (base64 Ed25519 over the DSSE PAE of its
    canonical subject) against `public_key_bytes`. Returns an empty list on
    success, else a list holding one fail-closed error string. Never
    raises: any decode/verification failure is reported as a rejection."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    signature_b64 = obj.get("signature")
    if not isinstance(signature_b64, str) or not signature_b64:
        return ["signature verification failed: signature field is empty or not a string"]
    try:
        signature_bytes = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return ["signature verification failed: signature is not valid base64"]

    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, pae_bytes(obj))
    except (InvalidSignature, ValueError, TypeError):
        return ["signature verification failed: Ed25519 signature does not verify"]
    return []
