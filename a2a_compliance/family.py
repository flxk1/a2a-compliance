"""Committed snapshot of the public Loomground family repositories.

This is the ground truth `tests/test_family_assignment.py` checks
`COMPLIANCE_ROLES` (in `team.py`) and `roles/*.json` against.  It is a plain
data module -- no network access, importable offline, safe to import from
tests.

Regeneration
------------
This list is derived by cross-checking every public `flxk1` repository
against the family catalogue, then resolving the (rare) disagreement by
reading the repository itself:

    gh repo list flxk1 --visibility public --limit 200 --json name,description
    gh api repos/flxk1/loomground/contents/CATALOGUE.json \
        -H "Accept: application/vnd.github.raw" > CATALOGUE.json

A public repo is a family member if it appears in `CATALOGUE.json`'s
`repos` list.  As of this snapshot there is exactly one exception:

  * `loomground-composition` -- deprecated and archived (2026-09-16),
    superseded by this repository's own 8-role compliance team and A2A
    lifecycle.  Because it is deprecated it was *dropped* from
    CATALOGUE.json, but it is still a published Loomground-family artifact
    (its own README states "Family: Composition"), so it is included here
    and assigned a role (`conductor`, `required=False`) rather than
    silently dropped.  This is a judgment call, not a mechanical one --
    flag it for human re-confirmation if CATALOGUE.json's editorial policy
    on deprecated repos changes.

Excluded public repos, with reason:

  * `.github` -- account-level meta-repo (default community health files
    for the flxk1 GitHub account). Not in CATALOGUE.json and not a
    Loomground-family artifact; it ships no Loomground role, tool, skill
    or contract.

Snapshot taken 2026-09-27 against CATALOGUE.json
(sha e5ac0a6034bd75bcee0eeb698cd529728121da4d, 42 cataloged repos) plus the
one manually-confirmed addition above, for 43 total family repos.
"""

from __future__ import annotations

FAMILY_REPOSITORIES: tuple[str, ...] = (
    "5d-nd",
    "a2a-compliance",
    "effect-reconciliation",
    "enforcement-posture",
    "evidence-emitter",
    "governance-certification",
    "governance-layer",
    "loomground",
    "loomground-audit-chain",
    "loomground-brief",
    "loomground-collapse",
    "loomground-composition",
    "loomground-deontic",
    "loomground-drift",
    "loomground-epistemic",
    "loomground-erasure",
    "loomground-escalation",
    "loomground-factual",
    "loomground-falsifiability",
    "loomground-governance",
    "loomground-ingest",
    "loomground-lane",
    "loomground-legal",
    "loomground-lock",
    "loomground-mandate",
    "loomground-mcp",
    "loomground-norm",
    "loomground-patchbay",
    "loomground-plugins",
    "loomground-proxy",
    "loomground-ref",
    "loomground-solver",
    "loomground-topos",
    "loomground-versum",
    "loomground-vertical",
    "loomground-workspace",
    "norm-freshness",
    "obligation-discharge",
    "oversight-certificate",
    "oversight-ladder",
    "policy-compiler",
    "privacy-shield",
    "skill-governance-block",
)

EXCLUDED_PUBLIC_REPOSITORIES: dict[str, str] = {
    ".github": "account meta-repo (community health files); not in CATALOGUE.json, not a Loomground-family artifact",
}

assert len(FAMILY_REPOSITORIES) == len(set(FAMILY_REPOSITORIES)) == 43
