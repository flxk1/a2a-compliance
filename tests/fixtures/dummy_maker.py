"""A minimal, REAL maker that participates in the A2A control channel by polling.

Launched as a child process by `SubprocessSpawner` in the harness tests. It
builds a `ControlParticipant` bound to a `FileInbox` at the shared inbox root
(from the environment the spawner sets) and loops, draining the inbox at each
checkpoint and yielding cooperatively to a `halt`. It also writes a heartbeat
file each iteration so a test can confirm it is genuinely running.

Not test code itself (no assertions) — it is the maker under control.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

# Self-contained path bootstrap: repo root is two levels up (tests/fixtures/..).
ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from a2a_compliance import FileInbox, ControlParticipant  # noqa: E402


def _state_provider(include):
    state = {
        "mandate": {"purpose": "dummy maker under harness control"},
        "trajectory": [{"step": "spawned"}],
        "tools": {},
        "claims": [],
    }
    return {k: state[k] for k in include if k in state}


def main() -> int:
    inbox_root = os.environ["A2A_INBOX_ROOT"]
    session_id = os.environ["A2A_SESSION_ID"]
    compliance_actor = os.environ.get("A2A_COMPLIANCE_ACTOR", "compliance")
    heartbeat = os.environ.get("A2A_HEARTBEAT")  # optional file path

    maker = ControlParticipant(
        session_id=session_id,
        inbox=FileInbox(inbox_root),
        compliance_actor=compliance_actor,
        state_provider=_state_provider,
    )

    beat = 0
    # Safety ceiling so a leaked test process self-terminates (~30s).
    for _ in range(600):
        maker.checkpoint()            # honour any pending control messages
        if not maker.should_continue():  # cooperative yield on halt
            break
        beat += 1
        if heartbeat:
            Path(heartbeat).write_text(str(beat), encoding="utf-8")
        time.sleep(0.05)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
