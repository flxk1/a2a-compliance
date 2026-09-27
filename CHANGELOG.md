<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Changelog

## Unreleased

### Added

Admission and permit issuance. `wire.admission.admit` returns ADMITTED,
REVIEW_REQUIRED or REFUSED over stage receipts it verifies first: a prohibited
or undeclared action is refused, a reserved action is admitted only with a
human-approval receipt that verifies, is bound to the same action digest and is
authorised for that kind, and a plan that is only `ready` never admits.
`wire.admission.issue_permit` returns a signed, single-use `ExecutionPermit`
only for an ADMITTED action, and its nonce is spent once.

Mediated execution. `wire.executor.consume_and_execute` runs a governed effect
only against a valid `ExecutionPermit`: it verifies the permit, checks the tool
and arguments match what the permit bound, atomically spends the permit's nonce,
then executes through a host-supplied executor and records a signed
`ToolReceipt`. A missing or tampered permit, a replayed nonce, a permit expired
or revoked since admission, or mutated arguments each produce no effect. A
subprocess conformance adapter ships as an example, outside the installed
package.

Postflight assurance. `wire.reconciliation.reconcile` verifies the permit and
every tool receipt, then compares their effects against a host-supplied,
independently observed set; a missing, unexpected or mismatched effect is a
residual and the signed `Reconciliation` is not clean. `wire.certification.certify`
issues a signed `OversightCertificate` only when the permit verifies at an
enforcement grade, the tool receipts verify and bind the action, the
reconciliation is clean, every blocking obligation carries a verified
`ObligationDischargeReceipt` (a bare string is no longer evidence of discharge),
every mandatory source is fresh, and the certifying identity differs from the
permit issuer, the reconciler, the tool executors and the approver; a successful
tool receipt alone never certifies. `wire.audit_chain.audit_chain_verify` detects
removal, reorder or mutation of any object in a run's assurance chain. Two
additive wire schemas, `ObligationDischargeReceipt` and `OversightCertificate`,
are added; no existing schema changed, and an envelope naming an unknown type is
refused.

Conformance kit and enforcement-grade profile. `wire.conformance_kit.run_conformance`
drives the whole pipeline -- plan, admit, permit, execute, reconcile, certify --
through host-supplied ports and reports, as end-to-end checks, that a valid run
certifies and that each enforcement guarantee fails closed. The profile reports
a deployment's grade as `advisory`, `mediated` or `platform`: `mediated`
requires both the observed bypass-rejection and the host's attestation that the
tool has no path around the proxy, since the kit cannot observe that structural
fact itself.

Authenticated control channel. A `ComplianceAgent` configured with a
`trust_store` and a `signer` stamps every outbound envelope with a fresh
`nonce`, an `expires_at` (300 seconds ahead by default) and its `key_id`, and
signs it with Ed25519 through `wire.signing` (`envelope.stamp_and_sign`). A
`ControlParticipant` configured with a `trust_store` applies an envelope only
when its key resolves and is bound to `A2AControlMessage`, the sender's role and
an identity equal to the envelope's `from_.actor`, the signature verifies, it has
not expired, its `(sender, nonce)` pair is new to the `NonceStore`, and
`authorize()` allows the verb; any other envelope is never applied and is
answered `ack{accepted: false}` with the reason. Without the `crypto` extra an
authenticated participant rejects every envelope. The four
fields are optional in `schema/a2a-control-message.schema.json` and omitted from
a bare envelope.

Sender-constrained permits. `wire.issue_permit` accepts `aud` and `cnf`
(RFC 7800 confirmation, `cnf.jkt` an RFC 7638 thumbprint of the executor's
Ed25519 key), only together. `wire.consume_and_execute` runs a permit carrying
either only for the executor identity `aud` names, presenting an Ed25519 proof
of possession by that key over the permit's `subject_digest` and nonce; a
mismatch or a missing or invalid proof produces no effect and leaves the nonce
unspent. `wire.signing` gains `okp_jwk`, `jwk_thumbprint`,
`cnf_jkt_for_public_key` and `verify_proof_of_possession`.

Pinned governance block. `GovernanceBlock.digest()` is the RFC 8785 digest of
the block's boundary, and `sign_governance_block` returns a
`SignedGovernanceBlock` a policy author signs. Given one, `wire.admit` refuses
admission when the block in force does not hash to the signed digest, when the
signing key's bound identity is the plan's maker or differs from the author the
block names, or when the signing key is not bound in the `TrustStore` to
`GovernanceBlock`, the policy-author role and an identity: a tampered,
maker-signed, unbound or digest-mismatched block makes `admit` return REFUSED,
checked before the approval gate, since no human review can repair a forged
authority. On success the permit carries `governance_block_digest`. The `ExecutionPermit` schema gains
the optional `aud`, `cnf` and `governance_block_digest` fields, and the
`ContextManifest` schema the optional `governance_block_digest`.

Conformance scenarios for the channel, the permit and the pin, each tagged.
`wire.run_conformance` adds scenarios for a foreign executor, a missing proof of
possession, a forged control sender, a replayed `resume`, a halt without
approval, a tampered governance block, and a maker self-report offered as an
admission receipt, and for the exploits the key-bound identity and durable
nonce store close: `agent_key_signed_approval_rejected`,
`approver_identity_mismatch_rejected`, `governance_block_signed_by_maker_refused`,
`control_actor_identity_mismatch_rejected`, `replayed_halt_receipt_rejected`,
`control_replay_without_injected_nonce_store_rejected` and
`halt_receipt_scope_violation_rejected`. `run_conformance` now reports 27
scenarios. Every `ScenarioResult` carries an OWASP Agentic AI Top 10 (2026) id
(`ASI01`-`ASI10`) in `asi`, which is now a required field. None of the new
scenarios changes how `Profile` grades a deployment.

Key-bound identity. `TrustBinding` gains `identity`, the principal a key speaks
for, set in deployment configuration (`InMemoryTrustStore.add(..., identity=)`)
and never read from the signed object. Every check that decides who signed
compares against it: `wire.verification.verify_human_approval` accepts a
`HumanApprovalReceipt` only when its key is bound to the `human` role and to the
identity `approver.id` names, and returns that key-bound identity; a
`StageReceipt`'s `issuer` must equal its key's bound identity; a
`SignedGovernanceBlock`'s author must equal its key's bound identity and differ
from the maker; a control envelope's `from_.actor` must equal its key's bound
identity. A key bound to no identity fails each of these checks. It is still
accepted where `wire.verification.verify` asks only whether a key authorized
for the object type (and, for a `StageReceipt`, the role) signed an object, as
for an `ExecutionPermit`, `ToolReceipt` or `Reconciliation`; no claim about
which principal signed rests on that check.

Durable nonce store. `a2a_compliance.nonce_store.FileNonceStore` is a
stdlib-only, file-backed `NonceStore`: one `O_CREAT | O_EXCL` marker per
`(run_id, nonce)`, files 0600 under a 0700 directory. A `ControlParticipant` or
`ComplianceAgent` constructed with a `trust_store` and no `nonce_store` defaults
to one under its inbox root, so authenticated mode never skips the replay check,
and rejects an envelope or halt approval if the store has been removed.

### Changed

`ComplianceAgent.halt()` in authenticated mode (a `trust_store` configured)
no longer dispatches on `confirm=True`. It dispatches only with a
`HumanApprovalReceipt` that verifies through
`wire.verification.verify_human_approval` (a key bound to the `human` role and
to the approver identity the receipt names), whose `permitted_action_digest`
equals `envelope.halt_digest` for that halt, whose `scope` is `next-action` or
`session`, and whose key-bound approver is neither the sender nor the maker.
The receipt is single-use: its `(run_id, nonce)` is consumed from the agent's
`NonceStore` only after every other check passes, so a valid receipt authorises
exactly one halt. Otherwise the halt is surfaced to the human and not sent. In bare mode (no `trust_store`)
`confirm=True` still dispatches, and the maker answers every honoured message
with `mode: "advisory"`; in authenticated mode, with `mode: "authenticated"`.

`FileInbox` creates message files, their temporary files and sequence-claim
files with mode 0600; sequence claims were 0644 and message files followed the
process umask.

`docs/enforcement/threat-model.md` no longer lists signature verification and
revocation as open, names the module behind each guarantee added since E0, and
lists what remains open.

The README status line states both what `main` carries and how much of it is
tagged, and the interface lists the admission, execution, assurance and
conformance entry points alongside the boundary they do not cross: mediation
reaches only effects routed through the mediated executor, and dispatch,
enforcement, erasure and evidence writing stay host acts. The install paragraph
names the `crypto` extra and `referencing`. `tests/test_readme_claims.py`
re-derives every counted claim in the README -- test count, Python floor,
released version, extras, role/plane/repository counts -- from the collected
suite, `pyproject.toml`, the CHANGELOG and the package, so a claim that stops
being true fails the suite. `tests/test_wire_e5.py` expects the full, current
scenario set, and `tests/test_conformance_scenario_registry.py` pins the
canonical scenario names against a live `run_conformance()` report.

The intended-versus-observed effect comparison is the `effect-reconciliation`
plane's computation and reaches the receipt-gated lifecycle only as that plane's
role-owned `tool:effect_reconcile` receipt: `lifecycle.reconcile` folds
postflight receipts and compares no effects of its own.
`tests/test_effect_reconciliation_delegation.py` pins the boundary -- the
declared owner, the fail-closed requirement, the fold's indifference to any
effect digest it is handed, and the absence of an import of the plane -- so a
later consolidation of the comparison into the lifecycle fails the suite. No
public signature changed.

### Fixed

The compliance manifest omitted `loomground-composition`, a published family
repository. It is now assigned to `conductor` as an optional contract, and the
manifest assigns all 43 public family repositories exactly once.
`a2a_compliance/family.py`, mirrored in `family.json`, records the family list
the assignment is checked against, and `tests/test_family_assignment.py` fails
on a family repository left unassigned or assigned twice. README.md, llms.txt
and `docs/compliance-team.md` had stated three different repository counts;
each now states 43, and `tests/test_readme_claims.py` derives the count from
`COMPLIANCE_ROLES` and holds all three documents to it.

## 0.4.0

Signed receipt chain. Receipts are signed with Ed25519 over the same canonical
bytes their digest is taken from, so a signature and a digest cannot disagree.
A trust store binds a key to the role allowed to use it, a revocation store
withdraws one, and `verify_chain` walks a chain of receipts: it requires each
link to name its predecessor's `subject_digest`, recomputes that digest itself
rather than trusting the claim, and rejects a receipt re-parented onto a
different predecessor even when that receipt is well formed and correctly
signed. The link field lives on the two chain-bearing receipt types, not on the
common envelope, so its absence states that a receipt is the first in a chain
rather than that the concept does not apply.

### Fixed

Fixed: `from a2a_compliance.wire import verify` returned the `verify`
submodule object (non-callable) instead of the `verify` function when a
`wire` submodule had already been imported first, anywhere in the process.
The undocumented import path `a2a_compliance.wire.verify` no longer exists;
the module is renamed to `a2a_compliance.wire.verification`. The public
`verify` function export and `a2a_compliance.wire.__all__` are unchanged.

## 0.3.0

Enforcement wire contracts. `a2a_compliance.wire` defines the envelopes the
control plane exchanges — control request, execution permit, human-approval
receipt, stage receipt, tool receipt, reconciliation, revocation, context
manifest — each as a JSON schema with a verifier for expiry, digest match,
replay and role ownership, and conformance vectors covering the negative cases.
Digests are taken over a canonical serialisation, and `ControlPlan.action_digest`
now uses it, so a digest computed here and one computed by a host agree. A sync
test holds each schema against the dataclass it mirrors. The wire package is
imported lazily, so a bare install stays free of its schema dependencies.

## 0.2.0

Full-family compliance team: `ComplianceTeam` plans a maker action across the
eight roles, `CapabilityInventory` reports what the host actually serves, and
`ControlPlan` carries the repository coverage. Eight role contracts ship as
packaged, schema-validated JSON. The lifecycle is receipt-gated: `enforce_preview`
folds role-owned preflight receipts into admitted / hold / route-human / refuse,
and `reconcile` certifies only an admitted dispatch whose postflight receipts
match its action digest. The harness driver steers a real maker through injected
host callables. Planning, preview and reconciliation perform no dispatch.

## 0.1.0

First release. Compliance agents steer maker agents over an agent-to-agent control channel, keeping them aligned to the operator's values.
