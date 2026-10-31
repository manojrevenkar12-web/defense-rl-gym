"""The whole pipeline on the quick profile (CI): every step runs, reports are written, the gate's
grader floors hold. The full run is committed; this only proves the pipeline still works."""

import json

import pytest

from drg import config


@pytest.mark.slow
def test_quick_pipeline_end_to_end():
    from drg.evaluate.pipeline import run_all

    assert run_all("quick")
    r = json.loads((config.ROOT / "runs" / "quick" / "results.json").read_text())
    assert r["study"]["robust"]["invalid_accepted"] == 0.0
    assert {"study", "redteam", "rl", "heldout", "bench", "gate"} <= set(r)
    assert (config.ROOT / "runs" / "quick" / "REPORT.md").read_text().startswith("# Report")
    lines = (config.ROOT / "runs" / "quick" / "transcripts.jsonl").read_text().splitlines()
    assert all({"env", "seed", "messages", "reward"} <= set(json.loads(x)) for x in lines)
