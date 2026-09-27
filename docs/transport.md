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
cursor, so it is durable across process exit and delivers in order. Message files,
their temporary files and sequence-claim files are created with mode 0600, so a
mailbox's contents are readable only by the owning user; the mailbox directories and
the `.cursor` file follow the process umask.

## Authenticated and bare modes

The mode is set by configuration, not negotiated on the wire.

- **Bare mode** (the default: no `trust_store`). `ComplianceAgent` sends unsigned
  envelopes, and `ControlParticipant.checkpoint()` applies any well-formed envelope
  in its mailbox. Nothing is authenticated: every honoured message is answered with
  `mode: "advisory"` in its response body, and `halt` dispatches on `confirm=True`,
  an assertion of human approval made out of band.
- **Authenticated mode** (a `trust_store` configured). A `ComplianceAgent` with a
  `signer` stamps each outbound envelope through `envelope.stamp_and_sign`: a fresh
  `nonce`, an `expires_at` 300 seconds ahead by default, the signer's `key_id`, and
  an Ed25519 `signature` over the DSSE PAE of the envelope's RFC 8785 canonical
  subject (`wire/signing.py`), so the nonce and expiry are covered by the
  signature. A `ControlParticipant` with a `trust_store` applies an envelope only
  if all of the following hold: `key_id` resolves in the trust store; the key is
  bound to `A2AControlMessage`, to the sender's claimed role and to an identity
  equal to the envelope's `from_.actor`; the signature verifies; `expires_at` is
  in the future; the `(sender, nonce)` pair has not been seen by the `NonceStore`
  (a durable, file-backed `FileNonceStore` under the inbox root unless one is
  injected, never skipped, and recorded only after every other check passes); and `authorize()` allows the
  sender's role that verb. An envelope that fails any check is never applied; the
  maker answers `ack{accepted: false}` with the reason. An applied envelope is
  answered with `mode: "authenticated"`. A `ComplianceAgent` with a `trust_store`
  dispatches `halt` only with a `HumanApprovalReceipt` that verifies, is signed by
  a key bound to the `human` role and to the approver identity it names, is bound
  to `envelope.halt_digest` for that halt, carries the scope `next-action` or
  `session`, and is approved by an identity other than the sender and the maker;
  each receipt is consumed once, so it authorises a single halt. `confirm=True`
  alone does not dispatch.
- **Without the `crypto` extra.** Signature checks need `cryptography`. An
  authenticated participant that cannot import it rejects every envelope (fail
  closed); bare mode does not need it.

The four authenticated-mode fields (`nonce`, `expires_at`, `key_id`,
`signature`) are optional in `schema/a2a-control-message.schema.json` and omitted
from a bare envelope, so a bare envelope keeps its earlier shape.

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
