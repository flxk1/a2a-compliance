<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Transport — cooperative poll, and the opt-in live send/stop

Moved out of the README under the family README canon. Design: [`../SPEC.md`](../SPEC.md) §9, §11.

## Cooperative poll — the default, and its honest limit

The maker-side participant is the load-bearing piece. Delivery is cooperative: a
directive is delivered only when the maker reaches `ControlParticipant.checkpoint()`,
and a `halt` is a cooperative stop at the next checkpoint — not a forced kill. The
maker's own loop must consult `should_continue()` / `is_held()` and yield. A maker
that never checkpoints cannot be steered by this shim. A forced or instant stop is a
harness- or external enforcement-level capability the bare protocol does not promise; the shim is
written so it can bind to a real harness send/stop primitive later without changing
callers.

`FileInbox` is the transport: a directory of per-actor mailboxes keyed by session id,
with an `O_EXCL` sequence claim, an atomic publish (`os.replace`), and a per-mailbox
cursor, so it is durable across process exit and delivers in order.

## Live send/stop transport (`a2a_compliance.harness`)

`a2a_compliance/harness.py` is the enforceable counterpart to the cooperative poll —
an optional, opt-in transport for makers the fleet spawns. It is not on the default
import path (`import a2a_compliance` pulls in no harness or subprocess-spawn driver);
callers opt in with `from a2a_compliance import harness`. It satisfies the same
put/poll transport seam `FileInbox` does, so a `ComplianceAgent(inbox=transport)`
binds real send/stop without changing callers, delivering the identical `query-state`
/ `issue-directive` / `hold` / `resume` / `halt` envelopes.

Two honest tiers:

- **Spawn-owned maker** — a maker this transport launched. `deliver()` sends a
  directive over the file-inbox channel the maker drains at its checkpoints; `stop()`
  is a real termination of the child process
  (`StopResult(enforceable=True, mechanism="process-terminate")`).
- **Maker it did NOT spawn** — cooperative fallback: `deliver()` / `stop()` delegate
  to the plain `FileInbox`, observed at the maker's next checkpoint
  (`StopResult(enforceable=False, mechanism="cooperative-halt")`). The harness does
  not expose arbitrary live cross-session messaging, so it does not claim a forced
  kill of a maker it does not own.

### The driver seam

`Spawner` is the driver Protocol. `SubprocessSpawner` is the real, testable default
(a maker runs as a child process; `tests/fixtures/dummy_maker.py` is the test child).
`ClaudeHarnessSpawner` is a documented injection point for the Claude-Code harness —
spawn ~ the Agent tool, stop ~ TaskStop — which are host agent-tools rather than a
Python API, so it is a seam the host wires, not a working in-module driver:
unwired, `spawn()` raises `NotImplementedError` so the seam fails loudly.

Public names in the module: `DirectiveTransport`, `MakerSpec`, `MakerHandle`,
`Spawner`, `SubprocessMakerHandle`, `SubprocessSpawner`, `ClaudeHarnessSpawner`,
`StopResult`, `HarnessTransport`.
