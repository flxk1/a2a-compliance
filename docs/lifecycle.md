<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Receipt-gated lifecycle

`a2a_compliance.lifecycle` turns a `ControlPlan` into a non-mutating admission
preview and later reconciles a host dispatch. It consumes tool verdicts as
`StageReceipt` values; it does not reproduce any Loomground check.

## Binding

Every plan hashes `maker_id`, `target_kind` and `proposed_action` into
`action_digest`. Every stage receipt and host `ControlReceipt` must carry that
same digest. A receipt must also name the role that owns its capability. Digest
mismatch, role mismatch and duplicate receipt all route to a human.

Receipt status is one of:

- `SATISFIED` — requires an output digest.
- `NOT_APPLICABLE` — requires an explicit reason.
- `NOT_SATISFIED` — holds the action.
- `OPEN` or `ERROR` — routes to a human.

## Before dispatch

`enforce_preview(plan, receipts)` requires the 22 read/check preflight tools in
the full profile: evidence, policy, language projections, Solver,
diagnostics and Lane/Lock/Drift/Privacy. Erasure is deliberately excluded: it
is an effect requiring separate authority, not a routine check.

The result is `admitted`, `hold`, `route-human` or `refuse` and always contains
`dispatch_performed: false`. A corrective `steer` result holds the original
action until a corrected action receives its own digest and plan.

## After dispatch

Only the host can produce a `ControlReceipt`. `reconcile` requires the matching
prior `ADMITTED` preview, then consumes postflight receipts from Governance
Certification, 5d-nd, Enforcement Posture, Effect Reconciliation, Norm
Freshness, Obligation Discharge, Audit Chain and Evidence Emitter. A dispatch
that used human approval additionally requires `oversight_verify`.

Missing or non-satisfied postflight evidence yields `RECONCILED` but not
`CERTIFIED`. A mismatched or non-admitted dispatch routes to a human.
