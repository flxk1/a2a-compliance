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
