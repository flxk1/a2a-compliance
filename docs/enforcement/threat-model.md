# E0 threat model — enforcement wire contracts

Scope: `a2a_compliance/wire/`. Contracts and a pure verifier only. No signature
verification (E1), no admission decision (E2), no dispatch (E3), no
observation/certification (E4). This document is prose distilled from the
enforcement-layer plan's "Fixed trust boundary", "Wire contracts" and "State
machine" sections; it does not restate the full plan.

## Assets

- The **admitted action digest** (`action_digest`) — the exact thing a permit,
  approval or receipt is bound to. Anything that can be substituted after
  binding defeats every downstream check.
- The **policy bundle** and **evidence bundle** a decision was grounded
  against (`ContextManifest`), and the **capability inventory** / **runtime
  baseline** a decision assumed were true at admission time.
- The **single-use nonce**, scoped to `(run_id, nonce)` — the thing that
  prevents a valid, correctly-signed object from being replayed.
- **Human approval** (`HumanApprovalReceipt`) — a scarce, non-fabricable
  credential; the one thing that can move a reserved effect toward admission.
- The **enforcement grade claim** (`advisory` / `mediated` / `platform`) on an
  `ExecutionPermit` — a false claim of `mediated`/`platform` turns an
  unenforced action into one a downstream consumer trusts as enforced.
- **Revocation state** for a key, policy, permit or run.

## Principals

Four distinct identities, per the plan's fixed trust boundary. One identity
must not satisfy two of these roles in the same run:

- **Policy authors** — issue `ContextManifest`-referenced policy bundles.
- **Approvers** — issue `HumanApprovalReceipt`. A human, never the maker or
  the tool executor being approved.
- **Tool executors** — issue `ToolReceipt`; the identity that actually ran a
  tool (`ToolReceipt.executor`), which the plan requires may differ from the
  nominally requested tool.
- **Assurance signers** — issue `Reconciliation` and `Revocation`; the
  identity attesting to postflight state, never the actor whose action is
  being reconciled.

E0 does not enforce this separation (role bindings are deployment
configuration per the plan); it is named here so E1's trust-role binding and
E2's admission logic have a fixed vocabulary to enforce against, and so a
reviewer of a deployment's role config knows what to check.

## Attack paths (first threat model; plan-named)

| Attack | E0 mitigation | What E0 does *not* cover |
|---|---|---|
| **Forged receipt** | Schema validation rejects malformed shape; `subject_digest` recompute rejects any receipt whose claimed digest doesn't match its own canonical content. | Whether the `signature` over that digest is valid, or came from a trusted `key_id` — E1. |
| **Altered context** | Any change to a signed object's fields changes its canonical bytes and therefore its digest; a `ContextManifest` bound into a later object by digest cannot be silently swapped without that binding breaking. | E0 does not itself verify that a *consumer* actually checks the binding — that is E2 admission logic. |
| **Replay** | `NonceStore` port scoped by `(run_id, nonce)`; a second `verify()` of any object sharing a previously-consumed pair is rejected. | E0's `InMemoryNonceStore` is test-only and non-durable; a host needs a durable store, and atomic pre-dispatch consumption is E3. |
| **Confused deputy** | `ToolReceipt.tool` is the *actual* tool invoked (not the nominally requested one), and `ToolReceipt.executor` is a distinct principal from the requester — both are visible on the wire for a later comparison. | E0 does not perform that comparison; that is reconciliation logic (E4) over these receipts. |
| **Stale policy** | `expires_at` staleness check rejects any object presented past its own expiry. | E0 has no concept of a *policy's* freshness independent of the object's own `expires_at` — that is `norm-freshness` (E4-adjacent repo). |
| **Partial execution** | `ToolReceipt` carries `started_at`/`ended_at` per call, and `dispatch_id` binds multiple `ToolReceipt`s to one `ControlReceipt`; a caller can see the receipt set is incomplete. | E0 does not decide completeness or certify — E4. |
| **Adapter bypass** | `ExecutionPermit.enforcement_grade` is a first-class, explicit field: an adapter that cannot prevent an out-of-band call must not claim `mediated`/`platform`. | E0 does not test whether a running adapter's claimed grade is true — that is `enforcement-posture` / E3's deployment test. |
| **Key compromise** | `Revocation` schema exists for `key`/`policy`/`permit`/`run` plus an effective time. | E0 does not check a `Revocation` against anything (no revocation-list consumption); that wiring is E1/E2. |

E0 explicitly does not claim protection against a fully compromised host, per
the plan.

## Enforcement grades

`ExecutionPermit.enforcement_grade` is one of:

1. **`advisory`** — the caller may ignore the verdict; suitable only for
   analysis. Not enforcement.
2. **`mediated`** — every governed tool is reachable only through an
   enforcement proxy; bypass is tested and treated as a deployment failure.
3. **`platform`** — the host itself validates permits at its action boundary.

Only `mediated` and `platform` are enforcement. E0 defines the field and its
three values; it never issues a permit (see "Fixed trust boundary" below) and
so never claims a grade is *true* of a running deployment — that claim is
tested at E3/E5.

## Fixed trust boundary

`a2a-compliance` (this repository, including `wire/`) never:

- dispatches, kills, erases, or activates policy;
- uses a production signing key (E0 treats `signature` as an opaque string;
  no key material exists in this package);
- fabricates human approval (a `HumanApprovalReceipt` is only ever consumed
  here, never synthesised).

The host owns credentials, process control, network/file effects and the
final action boundary. Core decisions in this package are deterministic over
canonical inputs (`wire/canonical.py` has no I/O and no randomness); model
output, where a host has one, is evidence or a proposal, never an unsigned
authority signal.

`ready` (an existing `team.py`/`lifecycle.py` concept) is not admission, and
E0 never issues an `ExecutionPermit` — it defines the permit's *schema*, not
its issuance, which is E2 scope.

## Open items carried into E1/E2 (not decided here)

- Trust-root and role-binding configuration format (plan: "deployment
  configuration, never embedded as trusted payload data").
- DSSE/Ed25519 signature verification over `signature`.
- Whether/how a `Revocation` is consulted during verification (E0's
  `verify()` has no revocation-list parameter).
