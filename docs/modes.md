<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Modes, axes, and invariants

Moved out of the README under the family README canon. The full design is
[`../SPEC.md`](../SPEC.md).

## Two overriding invariants

1. **Everything works WITHOUT RVND.** RVND is optional enrichment (an enforced
   permit/hold/deny verdict plus a signed-chain audit), never a dependency.
2. **Every loomground repo is OPTIONAL and UNIVERSAL.** The fleet does not
   hard-depend on any loomground repo; it works without them and enriches when
   one is present (graceful degradation), consuming each as a general,
   host-agnostic capability.

The fleet's only hard footing is its own ctrl substrate: the A2A control channel
plus the role-based authority of the ctrl team-charter roster. Loomground
value-grounding and RVND enforcement are both optional planes on top.

Grounding is optional-at-runtime but canonical-when-used: when the fleet grounds
its criteria it uses loomground and never builds a parallel grounding layer; when
loomground is absent it degrades to role-based / advisory control.

## Two axes, kept separate

```
        compliance-fleet skill  (orchestration plane — this repo)
   query-state · issue-directive · hold · resume · halt   (compliance -> maker)
        report-state · ack · escalate                     (maker -> compliance)
        ┌───────────────────────┴───────────────────────┐
   AXIS A — the CHANNEL (A2A)               AXIS B — AUTHORITY (who may steer whom)
   ctrl / orchestration plane               role-based (team-charter) by default
   complements MCP (MCP = agent<->tools;    RVND-gated + chained when RVND present
   A2A = agent<->agent)
        ┌───────────────┴────────────────┐
   HARD FOOTING (bare)              OPTIONAL enrichment (both degrade, never crash)
   A2A channel + team-charter       loomground value graph (per-plane flags):
   role roster                      deontic·norm·mandate·escalation·proxy·falsifiability
                                    RVND adapter (no-op when absent):
                                    permit/hold/deny + signed chain
```

## Three modes

- **(a) bare** — no loomground, no RVND. Steer criteria = the compliance role's
  advisory judgement; authority = role-based. Fully functional alone.
- **(b) +loomground** — steer criteria are drawn from the grounded value graph
  (O/P/F deontic norms, mandate, escalation, proxy, falsifiability), per-plane,
  behind flags; advisory fallback per dimension when a plane is absent.
- **(c) +RVND** — the directive is additionally enforced (permit/hold/deny) and
  written to the signed chain. Phase 3; a declared, flag-gated seam today, with
  `enforcement` serialised as `null` on every message the package emits.

## What is built (SPEC §12.1–2)

1. **The A2A control-message contract** — envelope plus all eight verbs, validated
   against `schema/a2a-control-message.schema.json`. `grounding` and `enforcement`
   are `null` on the bare path; a receiver treats `null` as a valid state, never a
   failure, and ignores unknown fields (`a2a_compliance.envelope`,
   `a2a_compliance.schema`).
2. **Role-based authority** from the ctrl team-charter roster — a compliance role
   (`policy-compliance` / `grounding` / `verify`) may steer a maker it oversees; an
   out-of-role sender is denied; `halt` is authorized-but-reserved and is dispatched
   only with `confirm=True` after human approval (`a2a_compliance.authority`).
3. **The governance-block reader** — reads a maker's declared
   `skill-governance-block` and bounds steering: steer within `actions[]`, route
   `reserved[]` to the human, never direct into `prohibited[]` (an undeclared kind
   is refused as outside the boundary). Consumes the block; does not redefine it
   (`a2a_compliance.governance_block`).
4. **The maker-side cooperative-poll shim** — a maker polls a session-keyed
   file-backed inbox at its checkpoints and honours pending directives
   (`a2a_compliance.inbox`, `a2a_compliance.participant`), driven by the compliance
   send side (`a2a_compliance.channel`).
5. **Value grounding** — per-plane loomground consumption and the grounded
   steer/hold/escalate decision (`a2a_compliance.planes`,
   `a2a_compliance.grounding`); see [value-grounding.md](value-grounding.md).

RVND enforcement (Phase 3) is design only.

## Seams

- **skill-governance-block** — A2A steers a maker within the boundary the maker
  declares in its own governance block. This repo consumes that neutral spec; it
  does not redefine it.
- **ctrl-desk** — the desk's `steer` / `hold` / `launch` ops (today: recorded
  intent) emit A2A directives the maker honours. The desk is the human injection
  point.

## Neutral spec

The universal-and-optional ethos makes this a vendor-agnostic protocol, and the
natural neutral complement to `skill-governance-block` (that declares a maker's
boundary; this is the runtime control within it). SPEC §10 records the shape a
neutral publication would take: a neutral `spec/` core plus a `bindings/` appendix
(ctrl = the role-authority binding, loomground = the value-criterion binding,
RVND = the enforcement binding).

## Repository layout

```
a2a-compliance/
├── .claude-plugin/plugin.json          # ctrl-plane plugin ("skills": "./skills/")
├── skills/compliance-fleet/SKILL.md    # skill manifest + governance: block
├── schema/a2a-control-message.schema.json   # the A2A envelope
├── interfaces/a2a_control.py           # message contract + participant SEAM (Protocols)
├── interfaces/compliance_fleet.py      # value-plane consumption seam (Protocols)
├── a2a_compliance/                     # working package
│   ├── envelope.py                     #   message construction + wire serialization
│   ├── schema.py                       #   jsonschema validation (guarded)
│   ├── authority.py                    #   role-based authority (team-charter roster)
│   ├── governance_block.py             #   the governance-block reader
│   ├── inbox.py                        #   file-backed cooperative-poll inbox
│   ├── participant.py                  #   maker-side control-participant shim
│   ├── harness.py                      #   opt-in live send/stop transport + Spawner seam
│   ├── channel.py                      #   compliance-agent send side (+ ground_and_steer)
│   ├── planes.py                       #   per-plane loomground consumption
│   └── grounding.py                    #   derivation + steer/hold/escalate mapping
├── tests/                              # bare-mode end-to-end + value grounding
├── docs/                               # this directory
├── pyproject.toml                      # package + [schema]/[manifest]/[dev] extras
├── SPEC.md                             # the design
└── README.md
```
