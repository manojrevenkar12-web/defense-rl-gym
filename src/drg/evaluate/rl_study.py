"""Train the same policy on the naive and on the robust reward, then judge both by what a defender wanted.

Training uses `corp-small` bins from the training seed range. Evaluation uses a separate seed
range, three families (the training one, a larger network, a noisier one) and the blind held-out
family when it exists, and always scores with the robust reward and its parts: was the attack
stopped, how many innocent machines were cut off, how much of the attacker's foothold was isolated.
"""

from __future__ import annotations

import json
import time
from multiprocessing import get_context
from pathlib import Path
from typing import Any

import numpy as np

from .. import config
from ..soc import baselines


def _eval_seeds(n: int) -> list[int]:
    base = config.load("rl")["seed_base"]["eval"]
    return list(range(base, base + n))


def _baseline_eval(policy_name: str, fam: str, seeds: list[int], **kw: Any) -> dict[str, float]:
    from ..rl.ppo import summarise

    pol = baselines.POLICIES[policy_name]
    infos = []
    for s in seeds:
        if kw:
            infos.append(baselines.run(lambda e, o, m, r: pol(e, o, m, r, **kw), s, fam, "robust"))
        else:
            infos.append(baselines.run(pol, s, fam, "robust"))
    return summarise(infos)


def tune_analyst(fam: str, n: int = 60) -> float:
    """Pick the analyst's threshold on training seeds, by robust reward (a fair baseline)."""
    best, best_r = 0.6, -1e9
    for th in config.load("rl")["analyst_thresholds"]:
        r = _baseline_eval("analyst", fam, list(range(n)), threshold=th)["reward"]
        if r > best_r:
            best, best_r = th, r
    return best


def _rc(overrides: dict[str, Any] | None) -> dict[str, Any]:
    rc = dict(config.load("rl"))
    if overrides:
        rc["ppo"] = {**rc["ppo"], **{k: v for k, v in overrides.items() if k in rc["ppo"]}}
        rc.update({k: v for k, v in overrides.items() if k not in rc["ppo"]})
    return rc


def _train_job(args: tuple[str, int, str, dict[str, Any] | None, float]) -> dict[str, Any]:
    """Train one variant (config/rl.yaml: variants) with one seed; judge it on the robust reward."""
    import torch

    from ..rl.ppo import HostPolicy, PPOConfig, clone, evaluate, train

    torch.set_num_threads(1)
    variant, seed, out_dir, overrides, threshold = args
    rc = _rc(overrides)
    v = rc["variants"][variant]
    torch.manual_seed(seed)
    init, bc_acc = None, None
    cfg = PPOConfig(**rc["ppo"])
    if v.get("init") == "clone":
        bc = rc["clone"]
        init = HostPolicy()
        base = rc["seed_base"]["clone"] + 10_000 * seed
        bc_acc = clone(
            init,
            lambda e, o, m, r: baselines.analyst(e, o, m, r, threshold=threshold),
            rc["train_family"],
            list(range(base, base + bc["episodes"])),
            bc["epochs"],
            bc["lr"],
        )
    else:
        cfg.value_warmup = 0
    fams = list(rc["eval_families"])  # the held-out family is run once, separately (evaluate/heldout.py)
    clone_eval = {f: evaluate(init, f, "robust", _eval_seeds(rc["eval_episodes"])) for f in fams} if init is not None else None
    policy, curve = train(rc["train_family"], v["reward"], seed, cfg, seed_base=rc["seed_base"]["train"], credit=v["credit"], name=variant, init=init)
    torch.save(policy.state_dict(), Path(out_dir) / f"policy_{variant}_{seed}.pt")
    ev = {f: evaluate(policy, f, "robust", _eval_seeds(rc["eval_episodes"])) for f in fams}
    return {**v, "variant": variant, "seed": seed, "curve": curve, "eval": ev, "clone_accuracy": bc_acc, "clone_eval": clone_eval}


def run_rl_study(out_dir: str, workers: int = 2, log=print, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    rc = _rc(overrides)
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    th = tune_analyst(rc["train_family"], n=rc["clone"]["tune_episodes"])  # on training seeds; also the cloning teacher
    log(f"analyst threshold tuned on training seeds: {th}")
    jobs = [(r, s, out_dir, overrides, th) for r in rc["variants"] for s in rc["seeds"]]
    with get_context("spawn").Pool(min(workers, len(jobs))) as pool:
        runs = pool.map(_train_job, jobs)
    log(f"rl study: {len(runs)} training runs in {time.time() - t0:.0f}s")
    fams = list(runs[0]["eval"])
    base = {}
    for name in ("isolate_all", "do_nothing", "analyst"):
        kw = {"threshold": th} if name == "analyst" else {}
        base[name] = {f: _baseline_eval(name, f, _eval_seeds(rc["eval_episodes"]), **kw) for f in fams}
    res = {"runs": runs, "baselines": base, "analyst_threshold": th, "families": fams}
    (Path(out_dir) / "rl_study.json").write_text(json.dumps(res))
    for f in fams:
        for r in rc["variants"]:
            m = [x["eval"][f] for x in runs if x["variant"] == r]
            log(
                f"{f}: trained on {r}: robust reward {np.mean([x['reward'] for x in m]):+.3f}, contained {np.mean([x['contained'] for x in m]):.2f}, "
                f"innocent machines isolated {np.mean([x['benign_isolated'] for x in m]):.2f}"
            )
    return res
