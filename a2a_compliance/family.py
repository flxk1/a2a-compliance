"""Committed snapshot of the public Loomground family repositories.

This is the ground truth `tests/test_family_assignment.py` checks
`COMPLIANCE_ROLES` (in `team.py`) and `roles/*.json` against.  It is a plain
data module -- no network access, importable offline, safe to import from
tests.

Regeneration
------------
The family is defined as: every public, non-archived repository on the
`flxk1` GitHub account, minus `.github` (account metadata, not a
Loomground-family artifact).  An archived repository is never a member, even
if it was one before archival.

Regenerate/verify with:

    gh repo list flxk1 --visibility public --limit 300 --json name,isArchived

Snapshot taken 2026-09-27 against that command's output. It listed 44 public
repositories, of which 1 was archived (`loomground-composition`, archived
2026-09-16, superseded by this repository's own 8-role compliance team and
A2A lifecycle) and 1 is the account meta-repo (`.github`), leaving 42 family
repositories.

Excluded public repos, with reason:

  * `.github` -- account-level meta-repo (default community health files
    for the flxk1 GitHub account). Not a Loomground-family artifact; it
    ships no Loomground role, tool, skill or contract.

Archived public repos, with reason (excluded from the family; recorded here
only so tests can assert they stay excluded, not because they count toward
the family):

  * `loomground-composition` -- archived 2026-09-16. Its prior `conductor`
    role assignment in `team.py`/`roles/conductor.json` was removed in this
    correction: an archived repository is not a family member and must not
    be assigned a role.
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
    ".github": "account meta-repo (community health files); not a Loomground-family artifact",
}

ARCHIVED_PUBLIC_REPOSITORIES: dict[str, str] = {
    "loomground-composition": (
        "archived 2026-09-16; archived repos are excluded from the family "
        "regardless of prior membership"
    ),
}

assert len(FAMILY_REPOSITORIES) == len(set(FAMILY_REPOSITORIES)) == 42
assert not (set(FAMILY_REPOSITORIES) & set(EXCLUDED_PUBLIC_REPOSITORIES))
assert not (set(FAMILY_REPOSITORIES) & set(ARCHIVED_PUBLIC_REPOSITORIES))
