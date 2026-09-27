"""A durable, file-backed `NonceStore` (FIX 2c). stdlib only.

`wire.verification.NonceStore` (the `seen`/`record`/`consume` port) is an
INJECTED port: E0/E1/E2 define the shape, a host supplies a durable
implementation. This package's callers on the control channel
(`participant.ControlParticipant`, `channel.ComplianceAgent`) need
*something* durable to default to when a caller does not inject its own --
the alternative, discovered by the recorded `replay.py` exploit, is a
`ControlParticipant` configured with a `trust_store` but no `nonce_store`
silently skipping its replay check (`if self.nonce_store is not None: ...`),
which is a fail-OPEN gap in AUTHENTICATED mode.

The choice made here: default to `FileNonceStore`, not to rejecting
outright. Both readings satisfy "never silently skip replay checks in
authenticated mode"; a hard rejection would also make every authenticated
`ControlParticipant`/`ComplianceAgent` constructed without an explicit
`nonce_store=` unusable out of the box, which is a worse default for a
package whose whole point is a durable-by-default posture (the same
posture `inbox.FileInbox` already takes for the mailbox itself). See
`participant.py`/`channel.py`'s `__post_init__` for where this default is
actually wired in -- always overridable by passing an explicit
`nonce_store=` (e.g. a host's own database-backed store, or the shared
`wire.verification.InMemoryNonceStore` in tests).

One zero-byte marker file per `(run_id, nonce)` pair, created
`O_CREAT | O_EXCL` so the marker's very existence is an atomic,
process-crash-durable claim -- the same primitive `inbox.FileInbox` already
relies on for its own sequence numbers and published messages. The root
directory is created `0700` and every marker file `0600`: a nonce marker
records that a specific control-channel action has already been honoured,
which is itself sensitive replay-guard state and is never left
group/other-readable, including in the window before any rename (there is
none here -- the create-exclusive call itself is the atomic step, no
tmp-file/rename dance is needed for a zero-byte marker).
"""

from __future__ import annotations

import os
from pathlib import Path


def safe_component(value: str) -> str:
    """Filesystem-safe rendering of an arbitrary run_id/nonce/actor string
    (mirrors `inbox.FileInbox`'s own actor-id sanitisation)."""
    return "".join(c if (c.isalnum() or c in "-_.") else "_" for c in str(value))


class FileNonceStore:
    """A `wire.verification.NonceStore`-shaped, file-backed, durable default.

    `seen`/`record` (the two-step check-then-write `verify()` and
    `_verify_envelope` use) and `consume` (the atomic compare-and-set
    `ComplianceAgent._verify_halt_approval` uses for single-use receipts)
    share the same on-disk marker -- both ultimately rely on the same
    `O_CREAT | O_EXCL` atomicity. A caller should not mix `record` and
    `consume` semantics for the same `(run_id, nonce)` pair, exactly as
    `wire.verification.NonceStore`'s own docstring already requires of any
    implementation."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def _path(self, run_id: str, nonce: str) -> Path:
        name = f"{safe_component(run_id)}__{safe_component(nonce)}.nonce"
        return self.root / name

    def _create(self, run_id: str, nonce: str) -> bool:
        """Atomically claim the `(run_id, nonce)` marker: True the first
        time, False on every call after that -- including concurrent /
        racing ones, since `O_CREAT | O_EXCL` is a single atomic syscall."""
        path = self._path(run_id, nonce)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return False
        os.close(fd)
        return True

    def seen(self, run_id: str, nonce: str) -> bool:
        return self._path(run_id, nonce).exists()

    def record(self, run_id: str, nonce: str) -> None:
        self._create(run_id, nonce)

    def consume(self, run_id: str, nonce: str) -> bool:
        return self._create(run_id, nonce)
