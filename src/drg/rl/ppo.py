"""PPO for the incident-response feature view, optionally started from behaviour cloning.

The policy scores every host with a shared encoder (so it works for any network size up to
`max_hosts`), pools the hosts into a context, and picks one of: investigate a host, isolate a host,
wait, submit. Invalid actions are masked. Training is on-policy with GAE and the clipped objective.

`clone` fits the policy to a teacher's actions first (the rule-based analyst), the way RL on
language models starts from a supervised model rather than from scratch: from scratch, every
early mistake on the robust reward costs more than doing nothing, and the policy learns to do
nothing (docs/REPORT.md, ablation `robust_scratch`).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import numpy as np
import torch
from torch import nn

from .. import config
from ..soc.env import FEATURES, FeatureEnv


class HostPolicy(nn.Module):
    def __init__(self, n_feat: int = len(FEATURES) + 1, width: int = 64):
        super().__init__()
        self.enc = nn.Sequential(nn.Linear(n_feat, width), nn.Tanh(), nn.Linear(width, width), nn.Tanh())
        self.ctx = nn.Sequential(nn.Linear(2 * width + 1, width), nn.Tanh())
        self.inv = nn.Linear(2 * width, 1)
        self.iso = nn.Linear(2 * width, 1)
        self.glob = nn.Linear(width, 2)      # wait, submit
        self.value = nn.Sequential(nn.Linear(width, width), nn.Tanh(), nn.Linear(width, 1))

    def forward(self, obs: torch.Tensor, time_left: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        present = obs[..., -1:]                                  # (B, H, 1)
        h = self.enc(obs) * present                              # (B, H, W)
        n = present.sum(1).clamp_min(1.0)
        mean = h.sum(1) / n
        mx = (h - 1e3 * (1 - present)).max(1).values
        g = self.ctx(torch.cat([mean, mx, time_left[:, None]], -1))  # (B, W)
        hg = torch.cat([h, g[:, None].expand_as(h)], -1)
        logits = torch.cat([self.inv(hg)[..., 0], self.iso(hg)[..., 0], self.glob(g)], -1)
        return logits, self.value(g)[:, 0]


@dataclass
class PPOConfig:
    iterations: int = 120
    episodes_per_iter: int = 48
    gamma: float = 0.99
    lam: float = 0.95
    clip: float = 0.2
    lr: float = 3e-4
    epochs: int = 4
    minibatch: int = 512
    entropy: float = 0.01
    value_coef: float = 0.5
    max_steps: int = 120
    value_warmup: int = 0      # iterations at the start that fit only the value head (after cloning)

    @classmethod
    def from_config(cls) -> PPOConfig:
        return cls(**config.load("rl")["ppo"])


def _masked(logits: torch.Tensor, mask: torch.Tensor) -> torch.distributions.Categorical:
    return torch.distributions.Categorical(logits=logits.masked_fill(~mask, -1e9))


def collect(policy: HostPolicy, family: str, reward: str, seeds: list[int], cfg: PPOConfig, greedy: bool = False, credit: str = "terminal") -> dict[str, Any]:
    obs_l, tl_l, mask_l, act_l, logp_l, val_l, rew_l, done_l, infos = [], [], [], [], [], [], [], [], []
    for seed in seeds:
        env = FeatureEnv(seed, family, reward, credit)
        obs, mask = env.reset()
        for _ in range(cfg.max_steps):
            o = torch.from_numpy(obs)[None]
            tl = torch.tensor([env.time_left()], dtype=torch.float32)
            m = torch.from_numpy(mask)[None]
            with torch.no_grad():
                logits, v = policy(o, tl)
                dist = _masked(logits, m)
                a = int(torch.argmax(logits.masked_fill(~m, -1e9))) if greedy else int(dist.sample())
                lp = float(dist.log_prob(torch.tensor([a])))
            (obs2, mask2), r, done, info = env.step(a)
            obs_l.append(obs)
            tl_l.append(env.time_left())
            mask_l.append(mask)
            act_l.append(a)
            logp_l.append(lp)
            val_l.append(float(v))
            rew_l.append(r)
            done_l.append(done)
            obs, mask = obs2, mask2
            if done:
                infos.append(info)
                break
        else:
            raise RuntimeError("episode exceeded max_steps")
    return {"obs": np.array(obs_l), "tl": np.array(tl_l, np.float32), "mask": np.array(mask_l), "act": np.array(act_l),
            "logp": np.array(logp_l, np.float32), "val": np.array(val_l, np.float32), "rew": np.array(rew_l, np.float32),
            "done": np.array(done_l), "infos": infos}


def gae(b: dict[str, Any], cfg: PPOConfig) -> tuple[np.ndarray, np.ndarray]:
    adv = np.zeros_like(b["rew"])
    last = 0.0
    for t in range(len(b["rew"]) - 1, -1, -1):
        next_v = 0.0 if b["done"][t] else b["val"][t + 1]
        delta = b["rew"][t] + cfg.gamma * next_v - b["val"][t]
        last = delta + cfg.gamma * cfg.lam * (0.0 if b["done"][t] else last)
        adv[t] = last
    return adv, adv + b["val"]


def summarise(infos: list[dict[str, Any]]) -> dict[str, float]:
    return {
        "reward": float(np.mean([i["reward"] for i in infos])),
        "contained": float(np.mean([i["contained"] for i in infos])),
        "benign_isolated": float(np.mean([sum(i["benign_isolated"].values()) for i in infos])),
        "dc_isolated": float(np.mean([i["benign_isolated"]["domain_controller"] for i in infos])),
        "caught": float(np.mean([i["compromised_isolated_share"] for i in infos])),
        "ticks": float(np.mean([i["ticks"] for i in infos])),
    }


def clone(policy: HostPolicy, teacher, family: str, seeds: list[int], epochs: int, lr: float, max_steps: int = 120) -> float:
    """Behaviour cloning: cross-entropy on the teacher's actions over its own trajectories."""
    obs_l, tl_l, mask_l, act_l = [], [], [], []
    for seed in seeds:
        env = FeatureEnv(seed, family, "robust")
        obs, mask = env.reset()
        rng = np.random.default_rng(seed)
        for _ in range(max_steps):
            a = teacher(env, obs, mask, rng)
            obs_l.append(obs)
            tl_l.append(env.time_left())
            mask_l.append(mask)
            act_l.append(a)
            (obs, mask), _, done, _ = env.step(a)
            if done:
                break
    obs_t, tl_t = torch.from_numpy(np.array(obs_l)), torch.tensor(tl_l, dtype=torch.float32)
    mask_t, act_t = torch.from_numpy(np.array(mask_l)), torch.tensor(act_l)
    opt = torch.optim.Adam(policy.parameters(), lr=lr)
    n, acc = len(act_t), 0.0
    for _ in range(epochs):
        perm = torch.randperm(n)
        for i in range(0, n, 512):
            ix = perm[i : i + 512]
            logits, _ = policy(obs_t[ix], tl_t[ix])
            loss = -_masked(logits, mask_t[ix]).log_prob(act_t[ix]).mean()
            opt.zero_grad()
            loss.backward()
            opt.step()
    with torch.no_grad():
        logits, _ = policy(obs_t, tl_t)
        acc = float((logits.masked_fill(~mask_t, -1e9).argmax(-1) == act_t).float().mean())
    return acc


def train(family: str, reward: str, seed: int, cfg: PPOConfig | None = None, seed_base: int = 0, log=print, credit: str = "terminal",
          name: str | None = None, init: HostPolicy | None = None) -> tuple[HostPolicy, list[dict[str, Any]]]:
    cfg = cfg or PPOConfig.from_config()
    torch.manual_seed(seed)
    rng = np.random.default_rng(seed)
    policy = init if init is not None else HostPolicy()
    opt = torch.optim.Adam(policy.parameters(), lr=cfg.lr)
    curve = []
    t0 = time.time()
    for it in range(cfg.iterations):
        seeds = [int(seed_base + rng.integers(0, 10**9)) for _ in range(cfg.episodes_per_iter)]
        b = collect(policy, family, reward, seeds, cfg, credit=credit)
        adv, ret = gae(b, cfg)
        adv_t = torch.from_numpy((adv - adv.mean()) / (adv.std() + 1e-8))
        ret_t = torch.from_numpy(ret)
        obs = torch.from_numpy(b["obs"])
        tl = torch.from_numpy(b["tl"])
        mask = torch.from_numpy(b["mask"])
        act = torch.from_numpy(b["act"])
        old = torch.from_numpy(b["logp"])
        n = len(act)
        for _ in range(cfg.epochs):
            perm = torch.randperm(n)
            for i in range(0, n, cfg.minibatch):
                ix = perm[i : i + cfg.minibatch]
                logits, v = policy(obs[ix], tl[ix])
                dist = _masked(logits, mask[ix])
                lp = dist.log_prob(act[ix])
                ratio = torch.exp(lp - old[ix])
                pg = -torch.min(ratio * adv_t[ix], torch.clamp(ratio, 1 - cfg.clip, 1 + cfg.clip) * adv_t[ix]).mean()
                vl = ((v - ret_t[ix]) ** 2).mean()
                if it < cfg.value_warmup:
                    loss = cfg.value_coef * vl
                else:
                    loss = pg + cfg.value_coef * vl - cfg.entropy * dist.entropy().mean()
                opt.zero_grad()
                loss.backward()
                nn.utils.clip_grad_norm_(policy.parameters(), 0.5)
                opt.step()
        s = summarise(b["infos"])
        s["iteration"] = it
        curve.append(s)
        if it % 10 == 0 or it == cfg.iterations - 1:
            log(f"[{name or reward} seed {seed}] it {it:3d} reward {s['reward']:+.3f} contained {s['contained']:.2f} "
                f"benign isolated {s['benign_isolated']:.2f} caught {s['caught']:.2f} ({time.time() - t0:.0f}s)")
    return policy, curve


def evaluate(policy: HostPolicy, family: str, reward: str, seeds: list[int]) -> dict[str, float]:
    cfg = PPOConfig.from_config()
    b = collect(policy, family, reward, seeds, cfg, greedy=True)
    return summarise(b["infos"])
