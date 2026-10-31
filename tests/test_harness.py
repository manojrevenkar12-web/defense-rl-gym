"""The tool-calling loop with a replay model, and the transcript format."""

import json

from drg.harness.agent import SYSTEMS, ReplayModel, make_env, run_episode, write_transcripts
from drg.patch.task import make_task
from drg.soc.world import make_scenario, truth


def test_patch_episode_with_the_reference_fix(tmp_path):
    t = make_task(5)
    calls = [("read_file", {"path": "REPORT.md"}), ("write_file", {"path": "service.py", "content": t.source("ref")}), ("submit", {})]
    ep = run_episode("patch", 5, ReplayModel(calls))
    assert ep["reward"] == 1.0
    roles = [m["role"] for m in ep["messages"]]
    assert roles[0] == "user" and roles[1] == "assistant" and roles[2] == "user"
    tu = ep["messages"][1]["content"][0]
    tr = ep["messages"][2]["content"][0]
    assert tu["type"] == "tool_use" and tr["type"] == "tool_result" and tr["tool_use_id"] == tu["id"]
    write_transcripts([ep], tmp_path / "t.jsonl")
    line = json.loads((tmp_path / "t.jsonl").read_text().splitlines()[0])
    assert line["env"] == "patch" and line["reward"] == 1.0


def test_hiding_the_evidence_earns_nothing():
    t = make_task(5)
    ep = run_episode("patch", 5, ReplayModel([("write_file", {"path": "service.py", "content": t.source("hack_tamper")}), ("submit", {})]))
    assert ep["reward"] == 0.0


def test_a_model_that_stops_without_submitting_is_still_graded():
    ep = run_episode("patch", 6, ReplayModel([("read_file", {"path": "service.py"})]))
    assert ep["reward"] == 0.0 and "reasons" in ep["result"]
    ep = run_episode("soc", 6, ReplayModel([("list_alerts", {})]))
    assert ep["result"]["contained"] is False


def test_soc_episode_with_an_oracle_script():
    tr = truth(make_scenario(21))
    calls = [("isolate_host", {"host": h}) for h in tr["hosts"]] + [("submit_report", {"compromised_hosts": tr["hosts"]})]
    ep = run_episode("soc", 21, ReplayModel(calls))
    # isolating every host the plan will reach stops the attack; hosts it never got to count as innocent
    assert ep["result"]["contained"] and ep["result"]["report_hosts_f1"] > 0


def test_tool_schemas_are_in_messages_api_shape():
    for kind in SYSTEMS:
        _, tools = make_env(kind, 0)
        for t in tools:
            assert set(t) == {"name", "description", "input_schema"} and t["input_schema"]["type"] == "object"
