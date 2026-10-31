"""The held-out rule, mechanically: blind sets are not edited after their first run."""

import hashlib
import json

import pytest

from drg import config
from drg.evaluate.redteam import status

ROOT = config.ROOT


def test_heldout_family_matches_its_recorded_hash():
    want = (ROOT / "heldout" / "heldout.sha256").read_text().split()[0]
    assert hashlib.sha256((ROOT / "heldout" / "heldout.yaml").read_bytes()).hexdigest() == want
    first = ROOT / "reports" / "heldout" / "first_run.json"
    if first.exists():
        assert json.loads(first.read_text())["spec_sha256"] == want


@pytest.mark.parametrize("name", list(config.load("patch")["redteam"]["sets"]))
def test_redteam_first_runs_match_the_patches_on_disk(name):
    first = ROOT / "reports" / "heldout" / f"{name}_first_run.json"
    if not first.exists():
        pytest.skip("not run yet")
    rec = json.loads(first.read_text())
    from drg.evaluate.redteam import grade_redteam

    now = grade_redteam(name, log=lambda *_: None)
    if status(name) == "heldout":
        assert now["summary"] == rec["summary"], "a held-out set's result changed: was the grader changed to pass it?"


def test_studied_sets_are_marked():
    assert status("redteam_v1") == "regression"
    assert config.load("patch")["redteam"]["current"] == "redteam_v2"
    assert status("redteam_v2") == "heldout"


def test_rl_training_never_sees_the_heldout_family():
    rc = config.load("rl")
    assert "heldout" not in rc["eval_families"] and rc["train_family"] != "heldout"
