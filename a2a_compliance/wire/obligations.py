"""E4 -- obligation discharge (plan: 'obligation-discharge' -- "Certification
requires all blocking obligations discharged").

Fixes an E2 caveat directly: E2's `admission.admit`/`issue_permit` only ever
took a caller-asserted `acknowledged_obligations: Iterable[str]` -- bare
strings the caller claimed were handled, never verified. This module makes
discharge a signed, independently checkable fact: `issue_discharge_receipt`
builds one (host-side, via an injected `Issuer` exactly like E2/E3's own
signers -- never a production key here), and `wire.certification.certify` counts an
obligation discharged ONLY when a matching `ObligationDischargeReceipt`
E1-`verify()`s (signature, trust binding, expiry, revocation) and binds the
same `action_digest` -- never from a caller-supplied list alone. A caller can
still pass whatever `blocking_obligations` id list it wants into `certify`;
what changed is that satisfying one now requires production of verifiable
evidence, not just naming it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from . import canonical
from .admission import Issuer


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def issue_discharge_receipt(
    obligation_id: str,
    action_digest: str,
    *,
    discharger: Issuer,
    run_id: str,
    nonce: str,
    expires_at: datetime,
    discharger_role: str = "obligation-discharger",
    issued_at: Optional[datetime] = None,
    schema_version: str = "1.0.0",
) -> dict:
    """Build and sign an `ObligationDischargeReceipt`. Never fabricated by
    `certify()` itself -- this is the only function in this package that
    produces one, and only when a host actually calls it with a real
    discharger identity."""
    issued = _as_utc(issued_at or datetime.now(timezone.utc))
    receipt = {
        "schema_version": schema_version,
        "type": "ObligationDischargeReceipt",
        "issuer": discharger.identity,
        "issued_at": issued.isoformat(),
        "expires_at": _as_utc(expires_at).isoformat(),
        "run_id": run_id,
        "nonce": nonce,
        "key_id": discharger.key_id,
        "obligation_id": obligation_id,
        "action_digest": action_digest,
        "discharged_by": {"id": discharger.identity, "role": discharger_role},
    }
    receipt["subject_digest"] = canonical.subject_digest(receipt)
    receipt["signature"] = discharger.sign(receipt)
    return receipt
