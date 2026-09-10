"""File-backed A2A inbox — the cooperative-poll transport (SPEC §9 option 1).

An inbox is a directory keyed by an actor's session id. A sender appends a
message; the addressee polls its own mailbox at a checkpoint and consumes new
messages in order. Durable (survives process exit), keyed by session id, and
binds to a real harness send/stop primitive later without changing callers.

This is deliberately the honest, within-harness mechanism: delivery happens
when the addressee polls, NOT instantly. See `participant.py` for the honest
limitation that follows (a `halt` is a cooperative stop at the next checkpoint,
not a forced kill).
"""

from __future__ import annotations

import json
import os
from pathlib import Path


class FileInbox:
    """A set of per-actor mailboxes under one root directory."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _mailbox(self, actor: str) -> Path:
        # actor ids are session-scoped tokens; keep the dir name filesystem-safe.
        safe = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in actor)
        box = self.root / safe
        box.mkdir(parents=True, exist_ok=True)
        return box

    def _next_seq(self, box: Path) -> int:
        """Allocate a strictly increasing sequence number via O_EXCL claim."""
        n = 0
        while True:
            claim = box / f".seq.{n:012d}"
            try:
                fd = os.open(claim, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
                os.close(fd)
                return n
            except FileExistsError:
                n += 1

    def put(self, to_actor: str, msg_wire: dict) -> int:
        """Append a message (on-wire dict) to `to_actor`'s mailbox. Returns seq."""
        box = self._mailbox(to_actor)
        seq = self._next_seq(box)
        payload = json.dumps(msg_wire, ensure_ascii=False, indent=2)
        tmp = box / f".tmp-{seq:012d}.json"
        final = box / f"{seq:012d}-{msg_wire.get('id', 'msg')}.json"
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, final)  # atomic publish
        return seq

    def _cursor_path(self, box: Path) -> Path:
        return box / ".cursor"

    def _read_cursor(self, box: Path) -> int:
        p = self._cursor_path(box)
        if not p.exists():
            return -1
        try:
            return int(p.read_text(encoding="utf-8").strip())
        except ValueError:
            return -1

    def _write_cursor(self, box: Path, seq: int) -> None:
        self._cursor_path(box).write_text(str(seq), encoding="utf-8")

    def poll(self, actor: str) -> list[dict]:
        """Return this actor's unconsumed messages in order and advance the
        cursor. A second poll with no new messages returns []."""
        box = self._mailbox(actor)
        cursor = self._read_cursor(box)
        pending: list[tuple[int, dict]] = []
        for f in box.glob("[0-9]" * 12 + "-*.json"):
            seq = int(f.name.split("-", 1)[0])
            if seq > cursor:
                pending.append((seq, json.loads(f.read_text(encoding="utf-8"))))
        pending.sort(key=lambda t: t[0])
        if pending:
            self._write_cursor(box, pending[-1][0])
        return [msg for _, msg in pending]

    def peek(self, actor: str) -> list[dict]:
        """Non-consuming read of all messages currently in a mailbox."""
        box = self._mailbox(actor)
        out: list[tuple[int, dict]] = []
        for f in box.glob("[0-9]" * 12 + "-*.json"):
            seq = int(f.name.split("-", 1)[0])
            out.append((seq, json.loads(f.read_text(encoding="utf-8"))))
        out.sort(key=lambda t: t[0])
        return [msg for _, msg in out]
