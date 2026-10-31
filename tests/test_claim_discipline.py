# Copyright 2026 Emily Echterhoff
# SPDX-License-Identifier: Apache-2.0

"""Regression checks for the current claim-audited documents, not historical records."""

from pathlib import Path
import re

import pytest

from cerberus.token import DecisionTokenSigner

ROOT = Path(__file__).resolve().parents[1]
CURRENT = [ROOT / "docs" / name for name in (
    "ONE_PAGE_PITCH.md", "EVALUATION_FRAMEWORK.md", "THREAT_MODEL.md",
    "SAFETY_INVARIANTS.md", "GAP_CLOSURE_PLAN.md", "CAPABILITY_INVENTORY.md",
)]


@pytest.mark.parametrize("path", CURRENT, ids=lambda path: path.name)
def test_current_documents_keep_research_maturity_boundary(path):
    text = path.read_text()
    assert "TRL 2–3" in text
    assert "production" in text.lower()


def test_current_pitch_and_evaluation_do_not_restore_audited_overclaims():
    pitch, evaluation = (CURRENT[index].read_text() for index in (0, 1))
    assert "unit tests proving" not in pitch
    assert "a formal threat model" not in pitch
    assert "Scope Reduction Rate" not in evaluation
    assert "approve, constrain, escalate" not in evaluation
    assert "approve, escalate, deny" in evaluation


def test_readme_architecture_and_changed_document_links_resolve():
    paths = CURRENT + [ROOT / "README.md"]
    assert "docs/architecture.md" not in (ROOT / "README.md").read_text()
    assert "## Architecture" in (ROOT / "README.md").read_text()
    for path in paths:
        for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", path.read_text()):
            if "://" in target or target.startswith("#"):
                continue
            assert (path.parent / target.split("#")[0]).exists(), (path, target)


def test_inventory_names_current_token_and_keeps_hmac_ed25519_distinct():
    inventory = CURRENT[-1].read_text()
    assert f"DecisionToken {DecisionTokenSigner.TOKEN_VERSION}" in inventory
    assert "HMAC" in inventory and "Ed25519" in inventory
    assert "in-memory" in inventory and "SQLite" in inventory
    assert "not independent human security validation" in inventory
