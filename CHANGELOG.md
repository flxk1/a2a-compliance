<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Changelog

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
