"""The policy network and a few PPO iterations (seconds)."""

import numpy as np
import pytest
import torch

from drg.rl.ppo import HostPolicy, PPOConfig, clone, collect, evaluate, gae, train
from drg.soc import baselines
from drg.soc.env import FeatureEnv


def test_policy_is_permutation_equivariant_over_hosts():
    torch.manual_seed(0)
    p = HostPolicy()
    obs, _ = FeatureEnv(3).reset()
    o = torch.from_numpy(obs)[None]
    tl = torch.tensor([0.5])
    n = int(obs[:, -1].sum())
    perm = torch.cat([torch.randperm(n), torch.arange(n, obs.shape[0])])
    H = obs.shape[0]
    a, v = p(o, tl)
    b, w = p(o[:, perm], tl)
    assert torch.allclose(a[0, :H][perm], b[0, :H], atol=1e-5)
    assert torch.allclose(a[0, H : 2 * H][perm], b[0, H : 2 * H], atol=1e-5)
    assert torch.allclose(v, w, atol=1e-5)


def test_gae_on_a_terminal_reward():
    b = {"rew": np.array([0, 0, 1], np.float32), "val": np.zeros(3, np.float32), "done": np.array([False, False, True])}
    adv, ret = gae(b, PPOConfig(gamma=1.0, lam=1.0))
    assert np.allclose(adv, [1, 1, 1]) and np.allclose(ret, [1, 1, 1])


def test_collect_and_a_short_training_run():
    cfg = PPOConfig(iterations=2, episodes_per_iter=4, minibatch=64)
    b = collect(HostPolicy(), "corp-small", "robust", [1, 2], cfg)
    assert len(b["infos"]) == 2 and b["obs"].shape[0] == len(b["act"])
    policy, curve = train("corp-small", "naive", 0, cfg, log=lambda *_: None)
    assert len(curve) == 2 and {"reward", "contained", "benign_isolated"} <= set(curve[0])
    s = evaluate(policy, "corp-small", "robust", [9, 10])
    assert set(s) >= {"reward", "contained", "benign_isolated", "caught", "dc_isolated"}


@pytest.mark.slow
def test_cloning_copies_the_analyst():
    torch.manual_seed(0)
    p = HostPolicy()
    acc = clone(p, lambda e, o, m, r: baselines.analyst(e, o, m, r, threshold=1.0), "corp-small", list(range(60)), epochs=30, lr=1e-3)
    assert acc > 0.85
