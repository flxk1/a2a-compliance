# E0 threat model — enforcement wire contracts

Scope: `a2a_compliance/wire/` and the A2A control channel
(`a2a_compliance/envelope.py`, `channel.py`, `participant.py`, `inbox.py`).
This document began as the E0 threat model (contracts and a pure verifier) and
is prose distilled from the enforcement-layer plan's "Fixed trust boundary",
"Wire contracts" and "State machine" sections; it does not restate the full
plan. The stages E0 deferred now exist in the package: signature verification
and revocation (E1: `wire/signing.py`, `wire/trust.py`, `wire/verification.py`),
admission (E2: `wire/admission.py`), mediated execution (E3: `wire/executor.py`)
and reconciliation and certification (E4: `wire/reconciliation.py`,
`wire/certification.py`). The attack table below names where each mitigation
now lives. "Guarantees added after E0" records the control-channel and
permit hardening, and "Open items" what is still not built.

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
reviewer of a deployment's role config knows what to check. Later stages
enforce parts of it: a pinned governance block must be signed by an identity
other than the maker (`wire/admission.py`, `_governance_block_findings`), a
halt approver must be a `human` identity other than the sender and the maker
(`channel.py`, `ComplianceAgent._verify_halt_approval`), and the certifying
identity must differ from the permit issuer, the reconciler, the tool executors
and the approver (`wire/certification.py`).

Identities are bound to keys. `TrustBinding.identity` (`wire/trust.py`) is the
principal a key speaks for, set in deployment configuration and never read
from the signed object. Every check that decides which principal signed
compares the object's claimed name against the signing key's bound identity
and roles, and fails closed when the key is bound to no identity: the approver
of a `HumanApprovalReceipt` (`wire.verification.verify_human_approval`: key
bound to the `human` role and to `approver.id`), the issuer of a `StageReceipt`
(`wire.verification`, `_trust_findings`), the author of a
`SignedGovernanceBlock` (`_governance_block_findings`) and the sender of a
signed control envelope (`participant.py`, `from_.actor`). A key bound to no
identity (`identity=None`, the default of `InMemoryTrustStore.add`) is still
accepted where `wire.verification.verify` asks only whether a key authorized
for the object type (and, for a `StageReceipt`, the role) signed the object,
as for an `ExecutionPermit`, `ToolReceipt`, `Reconciliation` or
`ContextManifest`. That check establishes only that some authorized key signed;
no claim about which principal signed rests on it.

## Attack paths (first threat model; plan-named)

| Attack | E0 mitigation | What E0 does *not* cover |
|---|---|---|
| **Forged receipt** | Schema validation rejects malformed shape; `subject_digest` recompute rejects any receipt whose claimed digest doesn't match its own canonical content. | Whether the `signature` over that digest is valid, or came from a trusted `key_id`. Covered in E1: when a `TrustStore` is passed, `wire.verification.verify` resolves `key_id`, checks the key is bound to the object type (and, for a `StageReceipt`, the role and the `issuer` identity), and verifies the Ed25519 signature over the DSSE PAE of the canonical subject (`wire/signing.py`, `wire/trust.py`). |
| **Altered context** | Any change to a signed object's fields changes its canonical bytes and therefore its digest; a `ContextManifest` bound into a later object by digest cannot be silently swapped without that binding breaking. | E0 does not itself verify that a *consumer* actually checks the binding — that is E2 admission logic. |
| **Replay** | `NonceStore` port scoped by `(run_id, nonce)`; a second `verify()` of any object sharing a previously-consumed pair is rejected. | E0's `InMemoryNonceStore` is test-only and non-durable. The control channel defaults to the durable, file-backed `FileNonceStore` (`nonce_store.py`) in authenticated mode; a host may inject its own. Atomic pre-dispatch consumption is built in E3: `wire.executor.consume_and_execute` spends the permit nonce through `NonceStore.consume`, a single compare-and-set. |
| **Confused deputy** | `ToolReceipt.tool` is the *actual* tool invoked (not the nominally requested one), and `ToolReceipt.executor` is a distinct principal from the requester — both are visible on the wire for a later comparison. | E0 does not perform that comparison; that is reconciliation logic (E4) over these receipts. |
| **Stale policy** | `expires_at` staleness check rejects any object presented past its own expiry. | E0 has no concept of a *policy's* freshness independent of the object's own `expires_at` — that is `norm-freshness` (E4-adjacent repo). |
| **Partial execution** | `ToolReceipt` carries `started_at`/`ended_at` per call, and `dispatch_id` binds multiple `ToolReceipt`s to one `ControlReceipt`; a caller can see the receipt set is incomplete. | E0 does not decide completeness or certify — E4. |
| **Adapter bypass** | `ExecutionPermit.enforcement_grade` is a first-class, explicit field: an adapter that cannot prevent an out-of-band call must not claim `mediated`/`platform`. | E0 does not test whether a running adapter's claimed grade is true — that is `enforcement-posture` / E3's deployment test. |
| **Key compromise** | `Revocation` schema exists for `key`/`policy`/`permit`/`run` plus an effective time. | E0 does not check a `Revocation` against anything. Covered in E1: when a `RevocationStore` is passed, `wire.verification.verify` rejects an object whose `key_id`, `run_id`, permit digest or (for a `ContextManifest`) policy bundle is revoked as of the reference time (`wire/trust.py`, `wire/verification.py`); admission, execution, reconciliation and certification pass their store through. The control-channel envelope check does not consult a `RevocationStore`. |

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
- uses a production signing key (signing goes through a host-injected
  `Issuer`; `wire.admission.dev_issuer` and `wire.signing.dev_sign_subject` are
  test-only, and no key material is packaged);
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

## Guarantees added after E0

Each is opt-in: a caller that configures none of it gets the earlier behaviour.

1. **Authenticated control channel** (`envelope.py`, `participant.py`,
   `channel.py`). A `ComplianceAgent` with a `trust_store` and a `signer`
   stamps every outbound envelope with `nonce`, `expires_at` (default 300
   seconds ahead) and `key_id`, and signs it through `wire/signing.py`
   (`envelope.stamp_and_sign`). A `ControlParticipant` with a `trust_store`
   honours an envelope only if its `key_id` resolves, the key is bound to
   `A2AControlMessage`, to the sender's claimed role and to an identity equal
   to the envelope's `from_.actor`, the Ed25519 signature verifies,
   `expires_at` is in the future, the `(sender, nonce)` pair has not been seen
   by the `NonceStore`, and `authorize()` allows the sender's role the verb.
   The replay check is never skipped in authenticated mode: a participant or
   agent constructed with a `trust_store` and no `nonce_store` defaults to a
   durable `FileNonceStore` under its inbox root (`nonce_store.py`), and one
   left with no store rejects the envelope. A rejected envelope is never applied; the maker
   answers `ack{accepted: false}` with the reason. Without the `crypto` extra
   an authenticated participant rejects every envelope. Without a
   `trust_store` (bare mode) envelopes are unsigned, and every honoured message
   is answered with `mode: "advisory"`.
2. **Approval-gated halt** (`channel.py`, `ComplianceAgent.halt`). With a
   `trust_store` configured, `confirm=True` no longer dispatches a halt. The
   halt dispatches only with a `HumanApprovalReceipt` that verifies through
   `wire.verification.verify_human_approval` against the agent's `trust_store`
   (signature, trust binding, expiry, revocation when the agent also has a
   `revocation_store`, and a key bound to the `human` role and to the approver
   identity the receipt names), whose `permitted_action_digest` equals
   `envelope.halt_digest` over this halt's sender, maker and `reason_ref`,
   whose `scope` is `next-action` or `session`, and whose key-bound approver
   is neither the sender nor the maker. The receipt is single-use: its
   `(run_id, nonce)` is consumed from the agent's `NonceStore` only after
   every other check passes, so a valid receipt authorises exactly one halt
   and a rejected one burns no nonce. Otherwise the halt is surfaced to the
   human and not sent. In bare mode `confirm=True`
   remains an advisory gate with no cryptographic binding.
3. **Sender-constrained permit** (`wire/admission.py`, `wire/executor.py`,
   `wire/signing.py`). `issue_permit` takes `aud` and `cnf` together (RFC 7800
   confirmation; `cnf.jkt` is the RFC 7638 thumbprint of the executor's
   Ed25519 key) and refuses either alone. When a permit carries either field,
   `consume_and_execute` requires `executor_identity == aud` and a proof of
   possession: an Ed25519 signature by the key `cnf.jkt` names over the DSSE
   PAE of the canonical `{permit_id, nonce}`, where `permit_id` is the
   permit's `subject_digest`. A mismatch or a missing or invalid proof
   produces no effect and leaves the nonce unspent.
4. **Pinned governance block** (`governance_block.py`, `wire/admission.py`).
   `GovernanceBlock.digest()` is the RFC 8785 digest of the block's boundary;
   `sign_governance_block` has a policy author sign it. Given a
   `SignedGovernanceBlock`, `admit()` refuses admission when the block in
   force does not hash to the signed digest, when the signing key's bound
   identity is the plan's maker or differs from the author the block names,
   when the signing key is not bound in the `TrustStore` to `GovernanceBlock`,
   the policy-author role (`policy-author` by default) and an identity, or
   when its signature fails. Each of these makes `admit` return REFUSED,
   checked before the approval gate: no human review can repair a forged
   authority. On success the digest is carried into the permit
   as `governance_block_digest`. `consume_and_execute` does not re-check it.

Control-channel files: `FileInbox` creates message files, their temporary
files and sequence-claim files with mode 0600 (`inbox.py`).

The conformance kit (`wire/conformance_kit.py`) exercises these guarantees:
`foreign_executor_rejected` and `missing_proof_rejected` for the permit,
`control_forged_sender_rejected`, `control_replayed_resume_rejected` and
`control_unapproved_halt_not_dispatched` for the channel,
`tampered_governance_block_not_admitted` for the pin, and
`self_report_never_satisfies_admission` for a maker's self-report. Seven
more exercise key-bound identity and the durable nonce store:
`agent_key_signed_approval_rejected`, `approver_identity_mismatch_rejected`,
`governance_block_signed_by_maker_refused`,
`control_actor_identity_mismatch_rejected`, `replayed_halt_receipt_rejected`,
`control_replay_without_injected_nonce_store_rejected` and
`halt_receipt_scope_violation_rejected`. `run_conformance` reports 27
scenarios in all. Every scenario carries an OWASP Agentic AI Top 10 (2026) id (`ASI01`-`ASI10`) in
`ScenarioResult.asi`. None of these scenarios changes how `Profile` grades a
deployment.

## Open items

- Trust-root and role-binding configuration format (plan: "deployment
  configuration, never embedded as trusted payload data"). The package ships
  only the `TrustStore`/`RevocationStore`/`NonceStore` ports, test-only
  in-memory implementations and the file-backed `FileNonceStore`; a host
  supplies a durable trust store and revocation store.
- Full DSSE envelopes and in-toto attestations. Signatures use the DSSE PAE
  construction over the canonical subject, but no object is wrapped in a DSSE
  envelope or emitted as an in-toto statement, and the `DSSE_PAYLOAD_TYPE`
  string is not yet aligned with other consumers.
- A transparency log for signed objects; `wire.audit_chain_verify` detects
  removal, reorder or mutation within a chain the host already holds, but
  nothing is published to an append-only log.
- Standard token profiles for the permit (for example a JWT or CWT encoding
  with DPoP); `aud`/`cnf` follow RFC 7800 semantics on this package's own
  wire format.
- An AuthZEN-style authorization decision interface; `authorize()` and the
  approver port are package-local.
- A binding to the A2A protocol's own transport and agent cards; the control
  channel runs over `FileInbox` or the opt-in harness transport.
- Certifier separation: `certify` compares the certifier's identity with the
  issuer, executor and approver names the permit, receipts, reconciliation
  and approval carry, and its key id with the permit's, reconciliation's and
  receipts' key ids; it does not resolve those names to the identities bound
  to their keys.
- Control-channel limits: the envelope check does not consult a
  `RevocationStore`; replay is checked through the `NonceStore`'s non-atomic
  `seen`/`record` pair; a `ComplianceAgent` with a
  `trust_store` but no `signer` sends unsigned envelopes, which an
  authenticated participant rejects; the mailbox directories and the
  `.cursor` file follow the process umask.
