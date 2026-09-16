<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Changelog

## Unreleased

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
