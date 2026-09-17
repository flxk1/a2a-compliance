"""Drift guard for the counted and capability claims in README.md.

The status line states a test count, a Python floor and the newest released
version; the install paragraph states the extras a consumer gets; the interface
bullets state how much of the enforcement chain exists. Each claim is
re-derived here from the thing it describes -- the collected suite,
pyproject.toml, the packaged API, the CHANGELOG -- so a claim that stops being
true fails the suite rather than waiting for a reader to notice it. llms.txt
repeats the install paragraph and the enforcement bullets verbatim, so it is
held against README.md instead of being re-checked against the code.

The test count is the *collected* count, which a `skipif` cannot move: a
deployment missing an optional value plane skips those tests but still collects
them, so the number is the same in a bare environment and a fully grounded one.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
LLMS = (ROOT / "llms.txt").read_text(encoding="utf-8")
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

INSTALL_PARAGRAPH = "Base install has zero dependencies. Extras:"


def _section(text: str, heading: str) -> str:
    start = text.index(heading) + len(heading)
    rest = text[start:]
    end = rest.find("\n## ")
    return rest if end == -1 else rest[:end]


def _status() -> str:
    return _section(README, "\n## Status\n").strip()


def _status_line() -> str:
    return _status().splitlines()[0]


def _install_paragraph(text: str) -> str:
    line = next(ln for ln in text.splitlines() if ln.startswith(INSTALL_PARAGRAPH))
    return line


def _pyproject_value(key: str) -> str:
    return re.search(rf'^{key} = "([^"]+)"', PYPROJECT, re.M).group(1)


def _optional_dependencies() -> dict:
    block = PYPROJECT[PYPROJECT.index("[project.optional-dependencies]"):]
    block = block[:block.index("\n[", 1)]
    extras = {}
    for name, body in re.findall(r"^(\w+) = \[(.*?)\]", block, re.M | re.S):
        extras[name] = re.findall(r'"([^"]+)"', body)
    return extras


def _collected_test_count() -> int:
    env = {k: v for k, v in os.environ.items() if k != "PYTEST_ADDOPTS"}
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "-p", "no:cacheprovider", "tests"],
        cwd=ROOT, capture_output=True, text=True, timeout=300, env=env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    match = re.search(r"(\d+) tests? collected", proc.stdout)
    assert match, proc.stdout
    return int(match.group(1))


def test_status_test_count_matches_the_collected_suite():
    claimed = int(re.search(r"(\d+) tests", _status_line()).group(1))
    assert claimed == _collected_test_count()


def test_status_python_floor_matches_pyproject():
    assert f"Python {_pyproject_value('requires-python')}" in _status_line()


def test_status_release_matches_the_packaged_version_and_changelog():
    version = _pyproject_value("version")
    assert f"latest tagged release {version}" in _status_line()
    assert f"The {version} tag predates that chain" in _status()
    released = re.findall(r"^## (?!Unreleased)(\S+)", CHANGELOG, re.M)
    assert released[0] == version


def test_status_untagged_claim_holds_only_while_unreleased_has_content():
    unreleased = _section(CHANGELOG, "\n## Unreleased\n")
    assert unreleased.strip(), (
        "the status line says the enforcement chain is recorded under "
        "`Unreleased`; that section is now empty"
    )
    assert "`Unreleased`" in _status()


def test_status_enforcement_chain_is_importable():
    from a2a_compliance import wire

    for name in ("admit", "issue_permit", "consume_and_execute",
                 "reconcile", "certify"):
        assert hasattr(wire, name), name


def test_status_boundary_claim_holds_without_a_host_attestation():
    from a2a_compliance.wire import Profile, dev_conformance_ports, run_conformance

    report = run_conformance(dev_conformance_ports())
    assert Profile(claimed_grade="mediated", report=report).observed_grade == "advisory"


def test_install_extras_match_pyproject():
    paragraph = _install_paragraph(README)
    extras = _optional_dependencies()
    assert _pyproject_value("name") and "dependencies = []" in PYPROJECT
    for name, specs in extras.items():
        assert f"`.[{name}]`" in paragraph, name
        if name == "dev":
            continue
        for spec in specs:
            assert spec in paragraph, spec
    composed = set(extras["schema"]) | set(extras["manifest"]) | set(extras["crypto"])
    assert set(extras["dev"]) == composed | {"pytest>=7"}
    assert "all three plus pytest>=7" in paragraph


def test_counted_interface_claims_match_the_package():
    from a2a_compliance import role_manifests
    from a2a_compliance.planes import ALL_PLANES
    from a2a_compliance.team import LOOMGROUND_REPOSITORIES

    assert len(role_manifests()) == 8 and "eight packaged" in README
    assert len(ALL_PLANES) == 6 and "six value planes" in README
    assert f"the {len(LOOMGROUND_REPOSITORIES)} repositories" in README


def test_llms_txt_repeats_the_readme_paragraphs_verbatim():
    assert _install_paragraph(LLMS) == _install_paragraph(README)
    for bullet in ("- admission:", "- execution:", "- assurance:", "- conformance:"):
        start = README.index(bullet)
        assert README[start:README.index("\n", start)] in LLMS, bullet
