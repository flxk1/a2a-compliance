# a2a-compliance — compliance agents control makers

*A loomground fleet to control your agents and protect your values.*

An **A2A (agent-to-agent) control protocol** plus a **compliance-fleet
contract**: a fleet of **compliance agents** watches the **maker** agents and
keeps them aligned to the operator's **values**, steering them over a control
channel — `query-state`, `issue-directive`, `hold`, `resume`, `halt` (compliance
→ maker); `report-state`, `ack`, `escalate` (maker → compliance).

## Two overriding invariants

1. **Everything works WITHOUT RVND.** RVND is *optional enrichment* (an enforced
   permit/hold/deny verdict + a signed-chain audit) — never a dependency.
2. **Every loomground repo is OPTIONAL and UNIVERSAL.** The fleet does not
   hard-depend on any loomground repo; it works without them and *enriches* when
   one is present (graceful degradation), consuming each as a general,
   host-agnostic capability.

The fleet's **only hard footing** is its own **ctrl substrate**: the A2A control
channel + the role-based authority of the ctrl team-charter roster. Loomground
value-grounding and RVND enforcement are BOTH optional planes on top.

Grounding is **optional-at-runtime but canonical-when-used**: when the fleet
grounds its criteria it uses loomground and never builds a parallel grounding
layer; when loomground is absent it degrades to role-based / advisory control —
it does not crash.

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
  advisory judgement; authority = role-based. **Fully functional alone.**
- **(b) +loomground** — steer criteria are *drawn from* the grounded value graph
  (O/P/F deontic norms, mandate, escalation, proxy, falsifiability), per-plane,
  behind flags; advisory fallback per dimension when a plane is absent.
- **(c) +RVND** — the directive is additionally enforced (permit/hold/deny) and
  written to the signed chain.

## Seams

- **skill-governance-block** — A2A steers a maker *within* the boundary the maker
  declares in its own governance block. This repo consumes that neutral spec; it
  does not redefine it.
- **ctrl-desk** — the desk's `steer`/`hold`/`launch` ops (today: recorded
  intent) emit A2A directives the maker honours. The desk is the human injection
  point.

## Status

**SPEC only.** This repo stages a design, not a build. See [`SPEC.md`](SPEC.md)
for the message contract, the value-plane consumption seam (with the honest
REAL-CONSUME vs STUB read per plane), the maker participant contract, the
authority model, the plane manifest, phasing, and honest gaps.

## Layout

```
a2a-compliance/
├── .claude-plugin/plugin.json          # ctrl-plane plugin ("skills": "./skills/")
├── skills/compliance-fleet/SKILL.md    # skeletal skill manifest + governance: block
├── schema/a2a-control-message.schema.json   # the A2A envelope (interface-only)
├── interfaces/a2a_control.py           # message contract + maker participant (interface-only)
├── interfaces/compliance_fleet.py      # value-plane consumption seam (interface-only)
├── SPEC.md                             # the design
├── README.md
├── REUSE.toml, LICENSES/               # licensing placeholders
```

## Neutral spec?

**Yes — recommended.** The universal-and-optional ethos already makes this a
vendor-agnostic protocol; it is the natural neutral complement to
`skill-governance-block` (that declares a maker's boundary; this is the runtime
control within it). At publication the recommendation is a neutral `spec/` core +
a `bindings/` appendix (ctrl = the role-authority binding, loomground = the
value-criterion binding, RVND = the enforcement binding). See SPEC §10.

Local only. No remote; publication is reserved for the owner.

Owner: Felix Krone (flxk1).
