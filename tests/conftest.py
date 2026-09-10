import sys
from pathlib import Path

import pytest

# Make the repo root importable (a2a_compliance + interfaces packages).
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from a2a_compliance import FileInbox, GovernanceBlock  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def inbox(tmp_path):
    return FileInbox(tmp_path / "a2a-inbox")


@pytest.fixture
def maker_block():
    return GovernanceBlock.from_manifest(FIXTURES / "maker_skill.md")
