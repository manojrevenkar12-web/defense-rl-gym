"""Reference policies for the feature view: what a learned policy has to beat (or should not copy)."""

from __future__ import annotations

import numpy as np

from .env import FEATURES, FeatureEnv

I = {f: k for k, f in enumerate(FEATURES)}


def isolate_all(env: FeatureEnv, obs, mask, rng) -> int:
    """Isolate every host, then submit: the naive reward's favourite."""
    iso = np.nonzero(mask[env.H : 2 * env.H])[0]
    return int(env.H + iso[0]) if len(iso) else 2 * env.H + 1


def do_nothing(env: FeatureEnv, obs, mask, rng) -> int:
    return 2 * env.H + 1


def random_policy(env: FeatureEnv, obs, mask, rng) -> int:
    return int(rng.choice(np.nonzero(mask)[0]))


def analyst(env: FeatureEnv, obs, mask, rng, threshold: float = 0.6) -> int:
    """A rule-based analyst: investigate hosts with any alert-like signal, isolate hosts whose
    evidence passes a threshold, wait while the picture develops, submit near the end."""
    H = env.H
    present = obs[:, -1] > 0
    alert = obs[:, I["office_shell"]] + obs[:, I["cred_dump"]] + obs[:, I["admin_logon_from_user_ws"]] + obs[:, I["odd_task"]] \
        + 0.5 * obs[:, I["outbound_mb"]] + obs[:, I["svc_cmd"]] + obs[:, I["logon_from_dump_host"]] + 0.5 * obs[:, I["shared_rare_infra"]]
    for i in np.argsort(-alert):
        if present[i] and mask[H + i] and alert[i] >= threshold and obs[i, I["investigated"]] > 0:
            return int(H + i)
    for i in np.argsort(-alert):
        if present[i] and mask[i] and alert[i] > 0.2:
            return int(i)
    return 2 * H if env.time_left() > 0.05 else 2 * H + 1


POLICIES = {"isolate_all": isolate_all, "do_nothing": do_nothing, "random": random_policy, "analyst": analyst}


def run(policy, seed: int, family: str, reward: str) -> dict:
    env = FeatureEnv(seed, family, reward)
    obs, mask = env.reset()
    rng = np.random.default_rng(seed)
    for _ in range(400):
        a = policy(env, obs, mask, rng)
        (obs, mask), r, done, info = env.step(a)
        if done:
            return {**info, "reward": r}
    raise RuntimeError("episode did not end")
