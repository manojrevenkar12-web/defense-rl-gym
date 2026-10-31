"""What the agent sees: generated, deterministic, and free of the grader's secrets."""

import json

from conftest import CWES
from drg.patch.env import PatchEnv
from drg.patch.task import make_task


def test_tasks_are_deterministic_in_their_seed():
    a, b = make_task(1234), make_task(1234)
    assert a.cwe == b.cwe and a.source("vuln") == b.source("vuln") and a.report() == b.report()


def test_every_generated_service_compiles(tasks):
    for t in tasks.values():
        for v in [*t.variants(), "vuln"]:
            compile(t.source(v), f"{t.cwe}-{v}", "exec")


def test_the_workspace_holds_no_reference_and_no_secret(tasks, tmp_path):
    for (cwe, two), t in tasks.items():
        ws = t.workspace(tmp_path / f"{cwe}-{two}")
        text = "".join(p.read_text() for p in ws.iterdir())
        world = json.dumps(t.spec.world)
        for token in ("canary-",):
            assert token not in text, f"{cwe}: a secret marker is visible to the agent"
        assert t.source("ref") not in text
        assert world == "{}" or world not in text


def test_access_rules_are_stated_when_the_code_cannot_show_them():
    t = next(make_task(s, "CWE-639") for s in range(50))
    assert "Access rule" in t.report() and "admins" in t.report()


def test_patch_env_episode_reference_fix_earns_reward():
    env = PatchEnv(77)
    obs = env.reset()
    assert "REPORT.md" in obs["files"]
    assert env.step("write_file", {"path": "support.py", "content": ""})[0]["error"]
    env.step("write_file", {"path": "service.py", "content": env.task.source("ref")})
    checks, _, _ = env.step("run_checks", {})
    assert checks["legitimate_request_ok"] and checks["attack_blocked"]
    out, r, done = env.step("submit", {})
    assert done and r == 1.0, out


def test_patch_env_unfixed_service_earns_nothing():
    env = PatchEnv(78)
    _, r, done = env.step("submit", {})
    assert done and r == 0.0


def test_all_six_classes_are_generated():
    assert len(CWES) == 6
    assert {make_task(s).cwe for s in range(200)} == set(CWES)
