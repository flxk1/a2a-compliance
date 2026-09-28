# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Validate `skills/compliance-fleet/SKILL.md`'s `governance:` block (the one
declaring `evidence-grounder`'s coordinate tools -- `tool:versum_coords`,
`tool:versum_cell`, `tool:nd_resolve`, see `coord_grounding.py`) against the
`flxk1/skill-governance-block` spec's own JSON Schema.

Schema location (honest, re-checkable, never guessed): a fresh clone of
`flxk1/skill-governance-block`, whose path this test reads from the
`SKILL_GOVERNANCE_BLOCK_SCHEMA` env var (pointed directly at
`schema/governance-block.schema.json`) or, failing that,
`SKILL_GOVERNANCE_BLOCK_REPO` (pointed at the clone's root, schema read from
`schema/governance-block.schema.json` under it). Neither set -> the test is
honestly skipped (never a fabricated pass, never a silent no-op green).

Validator: `jsonschema` -- already an optional dependency of this package
(`pyproject.toml`'s `schema`/`dev` extras; `tests/test_coord_grounding.py`
and `a2a_compliance/schema.py` already import it the same way), so this test
reuses it rather than hand-rolling a second validator.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SKILL_MD = ROOT / "skills" / "compliance-fleet" / "SKILL.md"


def _schema_path() -> Path | None:
    direct = os.environ.get("SKILL_GOVERNANCE_BLOCK_SCHEMA")
    if direct:
        return Path(direct)
    repo = os.environ.get("SKILL_GOVERNANCE_BLOCK_REPO")
    if repo:
        return Path(repo) / "schema" / "governance-block.schema.json"
    return None


def _governance_block(path: Path) -> dict:
    """The raw `governance:` mapping out of a SKILL.md's YAML frontmatter --
    unlike `GovernanceBlock.from_dict`, this keeps every key (including ones
    `a2a_compliance` does not itself interpret, e.g. `capabilities`), because
    the schema -- not this package's reader -- is the validation target."""
    import yaml  # PyYAML; already this package's `manifest`/`dev` extra

    text = path.read_text(encoding="utf-8")
    assert text.startswith("---"), f"{path}: no YAML frontmatter"
    _, _, rest = text.partition("---\n")
    front, sep, _ = rest.partition("\n---")
    assert sep, f"{path}: unterminated YAML frontmatter"
    data = yaml.safe_load(front) or {}
    block = data.get("governance")
    assert block is not None, f"{path}: manifest has no `governance` block"
    return block


@pytest.mark.skipif(
    _schema_path() is None,
    reason="no SKILL_GOVERNANCE_BLOCK_SCHEMA/SKILL_GOVERNANCE_BLOCK_REPO env var "
    "pointing at a flxk1/skill-governance-block clone's schema",
)
def test_skill_md_governance_block_validates_against_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = _schema_path()
    assert schema_path is not None and schema_path.is_file(), (
        f"schema not found at {schema_path} -- clone flxk1/skill-governance-block first"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    block = _governance_block(SKILL_MD)

    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(block)  # raises on the first violation


@pytest.mark.skipif(
    _schema_path() is None,
    reason="no SKILL_GOVERNANCE_BLOCK_SCHEMA/SKILL_GOVERNANCE_BLOCK_REPO env var "
    "pointing at a flxk1/skill-governance-block clone's schema",
)
def test_skill_md_governance_block_declares_the_three_coordinate_tools():
    block = _governance_block(SKILL_MD)
    capabilities = block.get("capabilities") or []
    for tool in ("tool:versum_coords", "tool:versum_cell", "tool:nd_resolve"):
        assert tool in capabilities
