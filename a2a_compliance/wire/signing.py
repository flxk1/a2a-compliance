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
import hashlib

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


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def okp_jwk(public_key_bytes: bytes) -> dict:
    """RFC 8037 OKP JWK for a raw 32-byte Ed25519 public key: the three
    required members (`kty`, `crv`, `x`) only -- no `kid`/`use`/etc, so this
    is exactly what `jwk_thumbprint` below hashes."""
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url_encode(public_key_bytes)}


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint: SHA-256 over the REQUIRED members only (for
    an OKP key per RFC 8037 + RFC 7638 s3.2: `crv`, `kty`, `x`), the member
    names in lexicographic order, no insignificant whitespace -- then
    base64url with no padding. Ignores any other member `jwk` may carry
    (e.g. `kid`), exactly as RFC 7638 requires. Reuses `wire.canonical`'s
    RFC 8785 serialization (which already sorts keys and omits whitespace,
    satisfying RFC 7638's own requirement) rather than growing a second JSON
    serialization path in this module."""
    members = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}
    digest = hashlib.sha256(canonical.canonical_bytes(members)).digest()
    return _b64url_encode(digest)


def cnf_jkt_for_public_key(public_key_bytes: bytes) -> str:
    """Convenience: the RFC 7638 thumbprint an `ExecutionPermit.cnf.jkt`
    carries for a given raw Ed25519 public key (quick win 5, sender-
    constrained permit / RFC 7800 `cnf`, DPoP-style)."""
    return jwk_thumbprint(okp_jwk(public_key_bytes))


def pop_pae_bytes(permit_id: str, nonce: str) -> bytes:
    """The exact bytes a proof-of-possession signature is computed over:
    the DSSE PAE of the RFC 8785 canonical `{permit_id, nonce}` pair (plan:
    quick win 5 -- "an Ed25519 signature ... over the canonical {permit_id,
    nonce}"). `permit_id` is the permit's own `subject_digest` -- the same
    stable identifier `wire.canonical.subject_digest` already computes for
    every wire object, never a second, separately-assigned id."""
    return _pae(DSSE_PAYLOAD_TYPE, canonical.canonical_bytes({"permit_id": permit_id, "nonce": nonce}))


def dev_sign_proof_of_possession(permit_id: str, nonce: str, private_key_bytes: bytes) -> dict:
    """TEST-ONLY. Builds a `{jwk, signature}` proof-of-possession object: an
    Ed25519 signature by `private_key_bytes` over `pop_pae_bytes(permit_id,
    nonce)`, alongside the RFC 8037 OKP JWK for the matching public key so a
    verifier can recompute its RFC 7638 thumbprint and check it against a
    permit's `cnf.jkt` (see `verify_proof_of_possession`). Never a
    production signer -- exactly like `dev_sign_subject`, this exists for
    conformance vectors and test fixtures only."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )
    signature = private_key.sign(pop_pae_bytes(permit_id, nonce))
    return {"jwk": okp_jwk(public_key_bytes), "signature": base64.b64encode(signature).decode("ascii")}


def verify_proof_of_possession(
    proof: dict, *, permit_id: str, nonce: str, expected_jkt: str,
) -> list[str]:
    """Verify a sender-constrained permit's proof of possession (quick win
    5): `proof["jwk"]` must be an Ed25519 OKP JWK whose RFC 7638 thumbprint
    equals `expected_jkt` (the permit's `cnf.jkt`), and `proof["signature"]`
    must be a valid Ed25519 signature by that same key over
    `pop_pae_bytes(permit_id, nonce)`. Returns an empty list on success, a
    list of fail-closed reasons otherwise. Never raises."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not isinstance(proof, dict):
        return ["proof of possession is not a JSON object"]
    jwk = proof.get("jwk")
    signature_b64 = proof.get("signature")
    if not isinstance(jwk, dict):
        return ["proof of possession jwk is missing or not a JSON object"]
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not isinstance(jwk.get("x"), str) or not jwk.get("x"):
        return ["proof of possession jwk is not a valid Ed25519 OKP JWK"]
    if not isinstance(signature_b64, str) or not signature_b64:
        return ["proof of possession signature is empty or not a string"]

    if jwk_thumbprint(jwk) != expected_jkt:
        return ["proof of possession key does not match the permit's cnf.jkt"]

    try:
        public_key_bytes = _b64url_decode(jwk["x"])
    except (binascii.Error, ValueError):
        return ["proof of possession jwk.x is not valid base64url"]
    try:
        signature_bytes = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError):
        return ["proof of possession signature is not valid base64"]

    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, pop_pae_bytes(permit_id, nonce))
    except (InvalidSignature, ValueError, TypeError):
        return ["proof of possession signature does not verify"]
    return []


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
