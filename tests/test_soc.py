"""The incident world, its tool view, the feature view and the two rewards."""

import json

import numpy as np
import pytest

from drg import config
from drg.soc import baselines
from drg.soc.env import FEATURES, FeatureEnv, SocEnv
from drg.soc.reward import running
from drg.soc.world import make_scenario, truth


def play(policy, seed, fam="corp-small", reward="robust", credit="terminal", **kw):
    env = FeatureEnv(seed, fam, reward, credit)
    obs, mask = env.reset()
    rng = np.random.default_rng(seed)
    total = 0.0
    for _ in range(400):
        (obs, mask), r, done, info = env.step(policy(env, obs, mask, rng, **kw))
        total += r
        if done:
            return info, total, env
    raise AssertionError("episode did not end")


def test_scenarios_are_deterministic():
    a, b = make_scenario(5), make_scenario(5)
    assert [h.name for h in a.hosts] == [h.name for h in b.hosts]
    assert a.events == b.events and [s.kind for s in a.plan] == [s.kind for s in b.plan]


@pytest.mark.parametrize("fam", ["corp-small", "corp-medium", "noisy-admins"])
def test_an_unopposed_attack_always_exfiltrates(fam):
    for s in range(10):
        sc = make_scenario(s, fam)
        sc.finish()
        assert sc.exfiltrated, s


def test_isolating_the_attackers_machines_in_time_stops_the_attack():
    for s in range(10):
        sc = make_scenario(s)
        for t in range(0, config.load("soc")["horizon"]):
            sc.advance(t)
            sc.isolated |= set(sc.compromised)
        sc.finish()
        assert not sc.exfiltrated, s


def test_naive_reward_is_maxed_by_isolating_everything_and_robust_reward_is_not():
    for s in range(10):
        naive, _, _ = play(baselines.isolate_all, s, reward="naive")
        robust, _, _ = play(baselines.isolate_all, s, reward="robust")
        assert naive["reward"] == 1.0 and naive["contained"]
        assert robust["reward"] < -1.0 and sum(robust["benign_isolated"].values()) > 3


def test_doing_nothing_loses_the_attack():
    info, _, _ = play(baselines.do_nothing, 3)
    assert not info["contained"] and info["reward"] < 0


def test_tuned_analyst_beats_isolate_all_on_the_robust_reward():
    a = np.mean([play(baselines.analyst, s, threshold=1.0)[0]["reward"] for s in range(30)])
    b = np.mean([play(baselines.isolate_all, s)[0]["reward"] for s in range(30)])
    assert a > b + 1.0


@pytest.mark.parametrize("seed", range(6))
def test_stepwise_credit_pays_the_same_total_as_terminal(seed):
    for pol in (baselines.isolate_all, baselines.random_policy, lambda e, o, m, r: baselines.analyst(e, o, m, r, threshold=1.0)):
        info_t, total_t, _ = play(pol, seed, credit="terminal")
        env = FeatureEnv(seed, "corp-small", "robust", "stepwise")
        env.reset()
        start = running(env.env.sc, "robust")
        info_s, total_s, _ = play(pol, seed, credit="stepwise")
        assert info_t["reward"] == pytest.approx(info_s["reward"])
        assert total_t == pytest.approx(total_s + start)


def test_feature_view_shapes_and_masks():
    env = FeatureEnv(1)
    obs, mask = env.reset()
    H = env.H
    assert obs.shape == (H, len(FEATURES) + 1) and mask.shape == (2 * H + 2,)
    n = len(env.names)
    assert obs[:n, -1].all() and not obs[n:, -1].any()
    assert mask[:n].all() and not mask[n:H].any() and mask[2 * H] and mask[2 * H + 1]
    (obs, mask), _, _, _ = env.step(H + 0)  # isolate host 0
    assert not mask[H + 0] and not mask[0] and obs[0, FEATURES.index("isolated")] == 1


def test_tool_view_never_shows_the_truth():
    env = SocEnv(9)
    first = env.reset()
    tr = truth(env.sc)
    leaks = {"compromised", "plan", "stolen", "attacker", env.sc.attacker_ip if False else "initial_access"}
    for tool, args in [("list_alerts", {}), ("search", {"limit": 50}), ("inspect_host", {"host": env.sc.hosts[0].name})]:
        out, r, done = env.step(tool, args)
        text = json.dumps(out)
        assert r == 0.0 and not done
        for k in leaks:
            assert f'"{k}"' not in text, (tool, k)
    assert set(tr) == {"hosts", "accounts", "initial_access"}
    assert "compromised" not in json.dumps(first)


def test_tool_view_report_scores_the_report_separately_from_reward():
    env = SocEnv(9)
    tr = truth(env.sc)
    out, r, done = env.step("submit_report", {"compromised_hosts": tr["hosts"], "compromised_accounts": tr["accounts"], "initial_access": tr["initial_access"]})
    assert done and out["report_initial_access_ok"] and 0 <= out["report_hosts_f1"] <= 1
    assert r == out["reward"]


def test_unknown_tools_and_hosts_are_errors_not_crashes():
    env = SocEnv(2)
    assert "error" in env.step("format_disk", {})[0]
    assert "error" in env.step("isolate_host", {"host": "nope"})[0]
    assert "error" in env.step("disable_account", {"user": "nobody"})[0]


def test_heldout_family_loads_from_its_own_file():
    from drg.soc.world import family

    f = family("heldout")
    assert "workstations" in f and f != family("corp-small")
