# a2a-compliance — SPEC (design, not a build)

**Status:** SPEC. Staged locally only (`git init`, no remote). No skill logic is
implemented; any code shown is interface-only.

**The mission (operator's framing).** *A loomground fleet to control your agents
and protect your values.* A **compliance fleet** watches the **maker** agents
and keeps them aligned to the operator's **values**. The control is an **A2A
(agent-to-agent) protocol**: compliance agents steer makers. When grounded, the
compliance agents' steering criteria are **drawn from the grounded value graph**
(O/P/F deontic norms — obligatory / permitted / forbidden — versioned,
defeasible); when ungrounded, they fall back to role-based / advisory control.

---

## 0. Two overriding invariants (non-negotiable — this SPEC is written to both)

1. **Everything works WITHOUT RVND.** RVND is *optional enrichment* (an enforced
   permit / hold / deny verdict plus a signed-chain audit) — never a dependency.
   The bare fleet (A2A channel + role authority) is fully functional alone.

2. **Every loomground repo is OPTIONAL and UNIVERSAL.**
   - **OPTIONAL** — the fleet MUST NOT hard-depend on any loomground repo. It
     works without any of them and *enriches* when one is present (graceful
     degradation). A missing value plane degrades to role-based / advisory
     control; it never crashes an op.
   - **UNIVERSAL** — each loomground capability is domain-neutral and
     host-agnostic. The fleet consumes each as a *general capability* through a
     stable interface, never as a fleet-specific fork.

   ⇒ **No "required" edge to Loomground or RVND is specified.** The fleet's ONLY
   hard footing is its own **ctrl substrate**: the A2A control channel + the
   role-based authority of the ctrl team-charter roster. Loomground
   value-grounding AND RVND enforcement are BOTH optional enrichment planes on
   top.

**Reconciliation with "loomground-first" (so this is not read as contradicting
it).** Grounding is **optional-at-runtime but canonical-when-used**. When the
fleet *does* ground its steering criteria, it uses loomground and never builds a
parallel grounding layer (consume, don't regrow). When loomground is absent, it
**degrades** to role-based / advisory authority — it does not fabricate a
value-graph and it does not fail. "Loomground-first" governs *how* the fleet
grounds *when it grounds at all*; it does not make loomground a load-bearing
dependency.

---

## 1. Frame — two axes kept separate

The design has two orthogonal axes. Conflating them is the recurring error; the
SPEC keeps them apart throughout.

### Axis A — A2A is the CHANNEL (plane = ctrl / orchestration)

A2A is the agent-to-agent control channel between a **compliance agent** and a
**maker**:

- compliance → maker: `query-state`, `issue-directive`, `hold`, `resume`,
  `halt`.
- maker → compliance: `report-state`, `ack`, `escalate`.

A2A **complements MCP**, it does not replace it. The division of labour:

| channel | endpoints | granularity | governed by |
|---|---|---|---|
| **MCP** | agent ↔ tools | one **action** at a time | RVND (when present) gates the action |
| **A2A** | agent ↔ agent (compliance ↔ maker) | the **fleet** / a maker's trajectory | ctrl coordinates; role authority steers |

MCP is where an individual action is planned/gated; A2A is where one agent
steers another. RVND lives on the MCP side (per-action verdicts) and, optionally,
enriches the A2A side (per-directive verdicts + chain) — see §6.

### Axis B — AUTHORITY is who may steer whom

Authority is *not* the channel. It answers: is this compliance agent permitted to
issue this directive to this maker?

- **Default (bare):** role-based, from the **ctrl team-charter roster** — the
  persistent core / compliance roles (`policy-compliance`, `grounding`,
  `verify`) oversee the maker (fresh-hire) sessions. No enrichment needed. This
  is the fleet's hard footing.
- **Enriched (RVND present):** the directive is additionally RVND-gated
  (permit / hold / deny) and written to the signed chain. Additive only.

Keeping A and B separate means: the *channel* works identically in all three
modes; only *what authorizes a directive on it* and *what criteria fill a
directive* change with enrichment.

---

## 2. The three operating modes

Every message and every op below is defined in all three modes. Mode (a) is
fully functional standalone.

| mode | value criteria come from | authority | audit |
|---|---|---|---|
| **(a) bare** — no loomground, no RVND | the compliance **role's** advisory judgement (charter roles) | role-based (team-charter) | none (advisory record only) |
| **(b) +loomground** | the **grounded value graph** (O/P/F deontic norms, mandate, escalation, proxy, falsifiability) | role-based (team-charter) | none (advisory record only) |
| **(c) +RVND** | as (a) or (b), plus | RVND permit/hold/deny **enforces** the directive | signed chain receipt |

- **(a) is the floor and it is complete.** A compliance agent with neither
  loomground nor RVND still queries maker state, forms an *advisory* steer/hold
  from its role's judgement (e.g. "this maker's trajectory looks off-mandate to
  the `policy-compliance` role"), issues the directive on the A2A channel, and
  the maker honours it. No op returns an error *because* an enrichment plane is
  absent.
- **(b) sharpens the criterion, not the channel.** loomground turns "looks off
  to me" into "violates obligation `O(bearer,action)` version `v`, evidence
  `…`". Same directive, same channel; a *grounded* reason replaces an *advisory*
  one.
- **(c) sharpens the authority.** RVND turns "the role is allowed to steer" into
  "this specific directive is permitted / held / denied, and here is the
  chained receipt". A `deny` blocks dispatch; absence of RVND means the directive
  dispatches on role authority alone.

---

## 3. A2A control-message contract

All messages share an envelope; each verb adds a typed body. The envelope and
bodies are the interface in `interfaces/a2a_control.py` and the JSON Schema in
`schema/a2a-control-message.schema.json`. This section is the normative
description.

### 3.1 Envelope (every message)

```
{
  "protocol": "a2a-compliance/0.1",
  "id": "<uuid>",                      // message id
  "correlates": "<uuid|null>",         // the message this replies to / continues
  "ts": "<rfc3339>",
  "from": { "actor": "<id>", "role": "<charter-role|maker>" },
  "to":   { "actor": "<id>", "role": "<charter-role|maker>" },
  "verb": "<one of the verbs below>",
  "body": { ... },                     // verb-specific
  "authority": { ... },                // see §5 — how this message is authorized
  "grounding": { ... } | null,         // see §4 — the grounded criterion, if any
  "enforcement": { ... } | null        // see §6 — RVND verdict/receipt, if any
}
```

- `grounding` is `null` in modes (a)/(c-without-b); populated in (b)/(c-with-b).
- `enforcement` is `null` in modes (a)/(b); populated in (c).
- A receiver **MUST** ignore unknown envelope fields (forward-compatibility) and
  **MUST NOT** treat a `null` `grounding`/`enforcement` as a failure — absence of
  an enrichment plane is a valid state, not an error.

### 3.2 compliance → maker verbs

| verb | body (shape) | semantics | bare (a) | +loomground (b) | +RVND (c) |
|---|---|---|---|---|---|
| `query-state` | `{ include: ["mandate","trajectory","tools","claims"] }` | ask the maker to report its current state | maker returns `report-state` | same | same |
| `issue-directive` | `{ instruction: str, kind: "correct"\|"constrain"\|"redirect", reason_ref }` | steer the maker's behaviour within its declared boundary (§7) | reason is the role's advisory judgement | `reason_ref` points at a grounded criterion (§4) | directive is RVND-gated before dispatch (§6) |
| `hold` | `{ scope: "next-action"\|"session", reason_ref, conditions?: [str] }` | soft-suspend the maker until `resume`/conditions met | advisory hold: coordination signal, no teeth | grounded reason attached | enforced hold if RVND `hold`/`deny` |
| `resume` | `{ hold_ref, note? }` | lift a prior hold | dispatched on role authority | same | RVND-gated (was the hold enforced?) |
| `halt` | `{ reason_ref, scope: "session", irreversible: true }` | stop the maker (reserved act) | **always** surfaced to the human first (§5, §8) | grounded reason attached | RVND-gated + chained |

- **`issue-directive` is the missing steer primitive** the ctrl-desk `steer` op
  needs (§8). Today the desk's `steer` bottoms out as *recorded intent*; an
  `issue-directive` message is the live send the maker honours.
- **`halt` is a reserved act in every mode.** Irreversible fleet-level steers are
  surfaced to the human for confirmation regardless of loomground/RVND presence,
  per the ctrl oversight rules. RVND, when present, additionally gates it; its
  absence does not lower the bar.

### 3.3 maker → compliance verbs

| verb | body (shape) | semantics |
|---|---|---|
| `report-state` | `{ mandate?: {...}, trajectory?: [step], tools?: {name:count}, claims?: [claim], provenance: "self-report" }` | answer a `query-state`; **honestly tiered** — a maker's self-report is `provenance:"self-report"` and is NEVER rendered as witnessed/observed |
| `ack` | `{ directive_ref, accepted: bool, note? }` | acknowledge a directive; `accepted:false` with a note is a *principled refusal* (see gaps §11) |
| `escalate` | `{ trigger, detail, requested: "guidance"\|"authority"\|"human" }` | the maker raises a decision it cannot make within its boundary — routed up the authority chain |

- `report-state` is the maker's own account and is **self-report tier** — the
  weakest falsifiability rank (§4, loomground-falsifiability). The compliance
  agent MUST NOT promote a self-report to a stronger provenance tier; where
  higher assurance is required it corroborates against harness/witnessed
  evidence (the ctrl-desk overlay, §8), never by trusting the maker's word.

### 3.4 Mode-behaviour invariant

Every verb is **total in mode (a)**: it has a complete, useful meaning with
neither loomground nor RVND. `grounding` and `enforcement` are additive envelope
planes; a receiver that sees them `null` behaves exactly as the bare protocol
specifies.

---

## 4. Compliance-fleet contract — deriving a steer/hold from values

A compliance agent derives a directive's *criterion* (the `reason_ref` and, in
mode (b), the `grounding` envelope block) from one of two sources:

- **mode (a) bare:** the compliance **role's** advisory judgement. The
  `policy-compliance` / `grounding` / `verify` roles reason from their charter
  brief and produce an *advisory* finding — "at_risk / violates / conforms" —
  with a human-readable reason and no grounded evidence pointer. Honestly
  labelled `grounding: null`.
- **mode (b) +loomground:** the criterion is **drawn from the grounded value
  graph** through the universal consumption interface in
  `interfaces/compliance_fleet.py`. This is the loomground-first path.

### 4.1 The value-plane seam (universal, optional, per-plane)

The fleet consumes each loomground value plane **behind a capability flag**
through one uniform interface. Each plane, when present, returns a solver
`Verdict` (`SATISFIED` / `NOT_SATISFIED` / `OPEN`) that maps to a steer decision;
when absent, the flag is off and the fleet uses the advisory fallback for that
plane. **No plane is required; any subset composes.**

Verdict → steer mapping (uniform across planes):

| solver `Verdict` | steer decision |
|---|---|
| `SATISFIED` | no steer — the maker is within values |
| `NOT_SATISFIED` | **steer / hold** — issue a `hold` or corrective `issue-directive` |
| `OPEN` | **escalate** — unassessed / insufficient; raise to human or higher authority (never treated as success) |

`OPEN` is a first-class outcome, never collapsed to pass or fail — matching the
solver's own contract and the fail-closed rule (charter §"Fail-closed by
construction").

### 4.2 The six value planes — honest read (REAL-CONSUME vs STUB) + fallback

All six were inspected (their real `src/` packages, public symbols, and passing
suites). **Verdict: all six are REAL-CONSUME today** — each has an installed,
importable package with a typed, callable API returning the common solver
`Verdict`. There is **no stub among the value repos.** (The genuine stubs in this
system are elsewhere — the maker-side A2A shim and the live-steering channel;
see §11.)

The four "operator" planes (mandate / escalation / proxy / falsifiability) all
return the same solver `Verdict` and fold via `fold_*` → `IssueAggregate`, so a
compliance agent can consume any subset and combine verdicts uniformly
(OPEN-dominant weakest-link, already implemented in `loomground_solver`).
`deontic` + `norm` are the *language / derivation* layer that produces the O/P/F
criterion; the four operator planes are independent *checks* over a maker's run.

| plane | REAL-CONSUME? | what the fleet consumes (the steer criterion) | advisory fallback when the flag is OFF |
|---|---|---|---|
| **loomground-deontic** | **REAL-CONSUME.** pkg `deontic`; `parse(text)->DeonticFormula`, `project(f)->{"operator":"O"\|"P"\|"F",...}`, `formula_from_fields(...)`, `compose([...]).conflicts`, `conflict_candidates([...])` | classify the **deontic force** (O/P/F) of a norm and detect that a maker action collides with a prohibition (same-bearer/same-action O-vs-F clash) | the role reads the operator's policy text and judges "this looks forbidden/required" in prose — no formal O/P/F, no conflict algebra |
| **loomground-norm** | **REAL-CONSUME.** pkg `loomground_norm`; `extract_rules(sentence)->[RuleFacet]`, `formula_from_rule(rule)->DeonticFormula`, `ObligationRegistry` + `ObligationScheduler.tick(...)->SchedulerReport` | turn prose policy into tracked O/P/F duties and track whether a maker's standing obligations are open / breached / discharged over time | the role hand-reads the policy each time; no extracted rule set, no live obligation-state tracking |
| **loomground-mandate** | **REAL-CONSUME.** pkg `loomground_mandate`; `detect(mandate, steps, *, evidence)->(Divergence,...)` (kinds: `ungrounded`/`defeats-purpose`/`out-of-mandate`/`unserved`), `fold_divergences(...)->IssueAggregate` | mandate/authority check: does the maker's trajectory serve the purpose it was given? `NOT_SATISFIED` when a step is out-of-mandate → **hold** | the role eyeballs the maker's `report-state` trajectory against its brief and judges drift advisorily |
| **loomground-escalation** | **REAL-CONSUME.** pkg `loomground_escalation`; `ceiling(factors,*,delegated,ladder)->Escalation`, `autonomy_verdict(requested,escalation)->Verdict`, `fold_autonomy(...)` | escalation-trigger / autonomy-ceiling: `NOT_SATISFIED` if the maker's requested autonomy exceeds the granted ceiling → **escalate/hold**; `escalation.binding` names the factors forcing the ceiling down | the role uses the charter grade ladder by hand (the maker's `grade`/`reserved` block, §7) — a coarser, non-weakest-link ceiling |
| **loomground-proxy** | **REAL-CONSUME.** pkg `loomground_proxy`; `check_proxies(proxies, readings)->(Substitution,...)` (kinds: `gamed`/`misleading`/`unchecked`/`tracking`), `fold_substitutions(...)` | proxy / value-alignment (Goodhart) check: `gamed` when a maker optimizes a proxy metric UP while the underlying value it stands for goes DOWN → **hold** | the role watches for obvious metric-gaming by inspection; no formal target-vs-proxy divergence detection |
| **loomground-falsifiability** | **REAL-CONSUME.** pkg `loomground_falsifiability`; `support_verdict(evidence,*,floor)->Verdict`, `best_support(...)`, `fold_support(...)`; `Falsifiability` IntEnum SELF_REPORT..REPLAYABLE, `SUPPORT_FLOOR=DECLARED_PLAN` | evidence-quality gate: `OPEN` (escalate) when a maker's claimed success rests only on self-report rather than observed/verified/replayable evidence | the role applies the `report-state` provenance tier by hand (self-report = weak) and asks for corroboration advisorily |

**Universal consumption rule.** The fleet consumes each plane as a *general
capability* — it passes generic inputs (a norm text, a mandate + trajectory, an
autonomy request + factors, proxy readings, evidence claims) and reads back a
generic `Verdict`. Nothing in the seam is fleet-specific; the same call would
serve any host. The seam lives in one module (`interfaces/compliance_fleet.py`)
and each plane import is guarded and flag-gated — absent/unimportable → the
flag is off and the advisory fallback runs (§4.3), never a crash.

### 4.3 Degradation contract

For each plane independently: `available()` → if false, the fleet uses that
plane's advisory fallback (right-hand column above) and stamps the finding
`grounding: null` for that dimension. A compliance directive may therefore be
*partly grounded* (some planes present, some advisory) — each dimension carries
its own honest provenance. The fleet NEVER fabricates a grounded verdict from an
absent plane, and NEVER blocks an op because a plane is missing.

---

## 5. Authority model

Authority answers *may this compliance agent issue this directive to this
maker*. It is independent of the channel (§1, Axis B).

### 5.1 Default — role-based (team-charter), the hard footing

- The **persistent core / compliance roles** of the ctrl team-charter —
  `policy-compliance` (GO / RESERVED / NO-GO before a boundary-relevant action),
  `grounding` (records + gates findings PASS/FAIL/OPEN), `verify` (independently
  refutes) — **are the compliance agents**. Makers are the **fresh-hire** maker
  sessions (`backend`, `frontend-qa`, `plane-engineer`, …) the core hires per
  task.
- Authority derives from the roster: a compliance role may `query-state`,
  `issue-directive`, `hold`, `resume` a maker it oversees. `halt` is a **reserved
  act** surfaced to the human (charter oversight rule: *the team never decides
  over the human's head*).
- This is the **only** hard-required authority substrate. It needs neither
  loomground nor RVND.

The `authority` envelope block in mode (a):

```
"authority": { "basis": "role", "role": "policy-compliance",
               "oversees": "<maker-id>", "reserved": false }
```

### 5.2 Enriched — RVND-gated

When RVND is present, the directive is additionally put to RVND's plan/gate
before dispatch; the `authority` block carries the verdict and the directive is
written to the signed chain (§6). RVND *sharpens* role authority into an enforced
permit/hold/deny; it never replaces the role basis, and its absence leaves the
role basis fully in force.

---

## 6. RVND enrichment (optional, flag-gated, no-op when absent)

RVND enriches the A2A directive path exactly as it enriches the ctrl-desk
`steer` op. A single adapter module is the **only** place `rvnd.*` is referenced;
it no-ops to an "absent" sentinel when RVND is unimportable.

- **On `issue-directive` / `hold` / `halt`:** if `rvnd.available()`, the
  directive is put to the RVND gate → `permit` | `hold` | `deny`
  (GO / CONDITIONAL / NO-GO). `deny` blocks dispatch; `hold` returns conditions;
  `permit` dispatches and attaches a chained `audit_id`. If not available, the
  directive dispatches on role authority alone (§5.1) and `enforcement` is
  `null`.
- **Advisory vs enforce split (inherited from ctrl-desk SPEC §5).** A pure
  *advisory preview* of the verdict (does not write the chain) is the default; an
  *enforce* call (writes the chain, yields `audit_id`) is an explicit,
  human-surfaced step. This keeps even the enriched path honest about when state
  is mutated.
- **Planes RVND adds to a directive record:** `witnessed` (the chain's own
  GO/CONDITIONAL/NO-GO verdict for the action) and the signed-chain tail. These
  are additive facts beside the maker's self-report and the fleet's advisory /
  grounded finding — **tiers are never fused** (a self-report is never rendered
  as witnessed).

The `enforcement` envelope block in mode (c):

```
"enforcement": { "engine": "rvnd", "verdict": "permit"|"hold"|"deny",
                 "gate_verdict": "GO"|"CONDITIONAL"|"NO-GO",
                 "audit_id": "<id|null>", "advisory": true|false }
```

---

## 7. Governance-block seam — steering within the declared boundary

A maker declares its governance boundary in its manifest as a **skill-governance
block** (the vendor-neutral spec at `skill-governance-block/`: `grade`,
`actions[]`, `reserved[]`, `prohibited[]`, `obligations[]`, `redress[]`,
`budget`, compiled to a well-formed loomground `.lg` patch). A2A is the
**runtime channel** that steers *within* that declared boundary. **This SPEC
consumes the block; it does not redefine it.**

- Before issuing a directive, the compliance agent **reads the maker's declared
  block** (plan-time reader role, governance-block SPEC §7): it may steer within
  `actions[]`, must route `reserved[]` kinds to the human, must never direct a
  maker into a `prohibited[]` kind, and carries `obligations[]` as accept-
  criteria on the maker's release.
- A directive that would push a maker outside its declared boundary is itself
  refused by the compliance agent (the block is the outer envelope; A2A steers
  inside it). Where RVND is present, the same block compiles to the `.lg` patch
  RVND enforces at action-time — one declaration, read plan-time by the
  compliance agent and enforced action-time by RVND, so they cannot disagree
  (governance-block SPEC §1).
- The block is itself **universal / vendor-neutral** — the same ethos as this
  protocol (see §10). The seam is: *A2A directive ⊆ the maker's declared
  governance boundary.*

---

## 8. ctrl-desk seam — the human injection point

`ctrl-desk` (the swarm Desk, sibling repo) is where a human surveys and steers
the fleet. Its `steer` / `hold` / `launch` ops today *bottom out as recorded
intent* — there is no live send/stop primitive (ctrl-desk SPEC §10 gap 3). **This
A2A protocol IS that primitive.**

- `ctrl-desk steer(session_id, action="message", payload)` → emits an A2A
  `issue-directive` to the maker; the maker's `accept-directive` participant
  contract (§9) honours it. `hold`/`resume`/`stop` map to A2A `hold` / `resume` /
  `halt`.
- `ctrl-desk` is the **human injection point** into the compliance fleet: a human
  at the Desk issues, through a compliance agent's authority, the same A2A
  directives an autonomous compliance agent would. Reserved acts (`halt`,
  destructive steers) surface at the Desk for confirmation in every mode.
- The Desk's overlay (harness transcript scrape + loomground 5D+nD fleet graph)
  is the **corroboration source** for a maker's self-reported `report-state`:
  where the maker says one thing and the harness-observed activity says another,
  the discrepancy surfaces — self-report is never trusted over witnessed/harness
  evidence.
- **Consistency note (invariant 2 applied to ctrl-desk).** ctrl-desk's own plane
  manifest currently declares `ctrl → loomground` as **required: true**
  (ctrl-desk SPEC §7). Under this SPEC's invariant 2 that edge should be
  **optional** — ctrl-desk's `check_conformity` should degrade to advisory
  role-based conformity when loomground is absent, exactly as this fleet does.
  Flagged for ctrl-desk to reconcile; not changed here (that repo is out of this
  SPEC's territory).

---

## 9. Maker-side control-participant contract (`accept-directive / report-state / halt`)

For A2A to control a maker, the maker must be an **A2A control-participant** that
exposes three capabilities:

```
accept-directive(msg)  -> ack{accepted, note?}     # honour an issue-directive/hold/resume within boundary
report-state(query)    -> report-state{...}        # answer query-state honestly, self-report tier
halt(msg)              -> ack{halted}               # stop on a halt directive
```

- **Honest gap (load-bearing).** Fresh-hire maker sessions (subagents spawned via
  the Agent tool / Workflow) **do not expose this contract today.** A subagent
  receives its prompt at spawn and returns a final report; there is no live
  inbound channel by which a running subagent receives an `issue-directive` or a
  `halt` mid-run. The maker-side participant is therefore a **named STUB** — the
  most load-bearing one in this SPEC (§11).
- **The shim.** Until makers natively participate, a thin **maker A2A shim**
  bridges the gap. Design options (to be decided at build):
  1. **cooperative poll** — the maker checks an A2A inbox (a file/queue keyed by
     its session id) at turn boundaries and honours pending directives. Works
     within the current harness; `halt` takes effect at the next checkpoint, not
     instantly.
  2. **spawn-time boundary** — directives that can only apply at spawn (mandate,
     grade, prohibited set) are compiled into the maker's initial prompt from the
     compliance agent's plan; mid-run steer degrades to (1).
  3. **harness send/stop primitive** — if/when ctrl exposes a real send/stop to a
     live session, the shim binds to it and `halt` becomes immediate.
- The shim is **honestly labelled**: in mode (a) a `halt` is a *cooperative*
  stop (the maker honours it at its next checkpoint), not a forced kill. A forced
  stop is a harness/RVND capability, not something the bare protocol can promise.

---

## 10. Should this be a NEUTRAL / vendor-agnostic spec? — YES

**Recommendation: author `a2a-compliance` as a neutral, vendor-agnostic protocol
spec, a sibling to `skill-governance-block`.** The argument:

1. **The universal ethos is already the design.** Invariant 2 makes every
   loomground plane an *optional, universal* capability behind a stable
   interface, and invariant 1 makes RVND an *optional* enrichment. A protocol
   whose every enrichment is optional and interface-mediated is, by construction,
   not bound to any one vendor.
2. **It composes with a neutral sibling.** `skill-governance-block` is already
   vendor-neutral: it declares a maker's boundary naming no orchestrator,
   enforcer, or host. A2A is the *runtime channel* that steers within that
   declared boundary — the natural neutral complement (§7). The pair reads as:
   *governance-block = the boundary declaration; a2a-compliance = the runtime
   control within it.*
3. **The normative core names no product.** The message contract (§3), authority
   model (§5), and maker participant contract (§9) are expressible without
   naming ctrl, loomground, or RVND. Those three appear only as **bindings**: ctrl
   as the reference orchestrator/roster, loomground as the reference value-graph,
   RVND as the reference enforcer.

**Consequence for the layout (mirrors skill-governance-block):** a neutral
`spec/` core (verbs, envelope, participant contract, authority, three-mode
degradation) + a `bindings/` appendix (one binding each: ctrl team-charter as the
role-authority binding, loomground planes as the value-criterion binding, RVND as
the enforcement binding). This SPEC.md is the working design; the neutral split
is the recommended shape at publication (a reserved act — not performed here).

---

## 11. Plane manifest (topology gate)

Per `repo-standards/topology.md`: `a2a-compliance` is an **orchestration-plane**
capability (it coordinates the fleet; the fleet's actions are what RVND governs
and what loomground grounds). Dependency direction points *toward the base* —
nothing depends back on it.

```yaml
# topology manifest entry (machine-readable form of the design)
repo: a2a-compliance
plane: orchestration                 # ctrl — the outer ring
allowed_edges:
  # NO required cross-plane edge. The ONLY hard footing is the ctrl substrate:
  # the A2A control channel + the team-charter role roster (ctrl-internal).
  - to: ctrl                         # the roster + A2A channel (same plane; the hard footing)
    kind: consumes
    required: true                   # intra-plane, not cross-plane
  - to: skill-governance-block       # consumes the maker's declared boundary (neutral spec)
    kind: consumes
    required: false
    optional: true
  - to: loomground                   # OPTIONAL — value criteria, behind per-plane flags
    kind: consumes
    required: false
    optional: true
  - to: rvnd                         # OPTIONAL — enforcement + chain, behind the adapter
    kind: consumes
    required: false
    optional: true
```

- **Gate passes.** There is **no required cross-plane edge**. Both cross-plane
  edges (`→ loomground`, `→ rvnd`) are `required: false` and isolated behind
  flag-gated adapters, so a topology check that verifies "the default build has
  no `loomground_*` / `rvnd.*` import outside its adapter module" passes even in
  a checkout with neither present. The `→ ctrl` edge is intra-plane (the A2A
  channel + roster are ctrl's own), not a cross-plane dependency. No edge points
  back up; no cycle.
- This is the machine-readable statement of invariant 2: the fleet's only hard
  footing is its own ctrl substrate.

---

## 12. Build phasing

1. **Phase 1 — bare A2A + role authority (ship first).**
   - The message contract (§3): envelope + verbs, `grounding`/`enforcement`
     `null`.
   - Role-based authority from the team-charter roster (§5.1).
   - The governance-block reader seam (§7): steer within the declared boundary.
   - The maker A2A shim (§9) — cooperative-poll option first (the honest,
     within-harness path).
   - ctrl-desk `steer`/`hold` → A2A `issue-directive`/`hold` (§8).
   - Advisory (role) criteria only. Fully functional with neither loomground nor
     RVND.
2. **Phase 2 — loomground value grounding (optional).** Land the per-plane seam
   (§4): flag-gated, universal consumption of any subset of the six REAL-CONSUME
   planes; `grounding` envelope populated when a plane is present; advisory
   fallback per dimension when absent. Purely additive.
3. **Phase 3 — RVND enforcement (optional).** Land the §6 adapter: directive
   permit/hold/deny + chained receipt + witnessed plane; advisory-vs-enforce
   split. Purely additive; Phase-1/2 behaviour unchanged when RVND is absent.
4. **Phase 4 (reserved, not this SPEC) — neutralize + publish.** Split into a
   neutral `spec/` core + `bindings/` appendix (§10). Publication is a reserved
   act for the owner.

---

## 13. Honest gaps / open questions

1. **Maker A2A participant is a STUB (load-bearing).** Fresh-hire subagents do
   not expose `accept-directive` / `halt` on a live inbound channel today (§9).
   Phase 1 depends on the cooperative-poll shim; `halt` is a *cooperative* stop
   at a checkpoint, not a forced kill, until a real harness send/stop primitive
   exists. This is the single most load-bearing gap.
2. **Live-steering channel (shared with ctrl-desk gap 3).** The concrete
   mechanism to deliver a directive to a *running* Claude session is not yet a
   named primitive. Until it is, `issue-directive` is delivered at turn
   boundaries (poll) or at spawn (compiled into the prompt), not instantly. Both
   SPECs share this open item; solving it once serves both.
3. **Maker refusal / `ack{accepted:false}`.** A maker may principledly refuse a
   directive (e.g. it judges the directive itself out-of-boundary). The
   arbitration — compliance-agent authority vs maker refusal — routes to
   `escalate` → human, but the precedence rule (does a grounded directive
   override a maker's refusal automatically?) is unspecified. Leaning: never
   auto-override a refusal; escalate to the human (consistent with the reserved-
   act posture).
4. **All six value planes are REAL-CONSUME — no value-plane stub.** This is a
   positive finding, but note the fleet has not yet been *integration-tested*
   against live plane instances end-to-end; the seam signatures are read from the
   packages, not exercised through the fleet. The interface risk is low
   (uniform `Verdict`), the integration risk is unmeasured.
5. **Which value graph / which policy is "the operator's values" by default.**
   How an operator declares *the* value graph the fleet grounds against (a
   loomground policy handle, a `.lg` patch, a versum scope) is unspecified —
   shared with ctrl-desk gap 6.
6. **Multi-operator / cloud fleet.** The role roster and harness overlay are
   local. A cloud or multi-machine compliance fleet needs an out-of-band roster
   and an A2A transport beyond the local inbox; out of scope for Phase 1.
7. **GDPR / provenance.** Session ids in A2A envelopes are pseudonymous personal
   data (per the ctrl-desk console ADR); retention/erasure of A2A message logs
   inherits the same questions; deferred but noted.
