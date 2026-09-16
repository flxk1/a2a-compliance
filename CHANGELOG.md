<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Changelog

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
