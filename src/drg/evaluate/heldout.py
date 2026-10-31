"""The blind held-out network family: trained policies and baselines, run once, first run kept."""

from __future__ import annotations

import json
import time
from typing import Any

from .. import config
from .pipeline import run_dir, sha256, write_json
from .rl_study import _baseline_eval, _eval_seeds, _rc

HELD = config.ROOT / "reports" / "heldout"


def run_heldout(profile: str, log=print) -> dict[str, Any]:
    import torch

    from ..rl.ppo import HostPolicy, evaluate

    spec = config.ROOT / "heldout" / "heldout.yaml"
    sha = sha256(spec)
    first = HELD / "first_run.json"
    if first.exists() and json.loads(first.read_text())["spec_sha256"] != sha:
        raise SystemExit("heldout/heldout.yaml changed after its first run; a changed set is a new set (AGENTS.md)")
    overrides = config.load("experiment")["profiles"][profile].get("rl")
    rc = _rc(overrides)
    rl_dir = run_dir(profile) / "rl"
    study = json.loads((rl_dir / "rl_study.json").read_text())
    seeds = _eval_seeds(rc["eval_episodes"])
    res: dict[str, Any] = {"policies": {}, "baselines": {}}
    for reward in rc["variants"]:
        for s in rc["seeds"]:
            p = HostPolicy()
            p.load_state_dict(torch.load(rl_dir / f"policy_{reward}_{s}.pt", map_location="cpu", weights_only=True))
            res["policies"][f"{reward}_{s}"] = evaluate(p.eval(), "heldout", "robust", seeds)
    for name in ("isolate_all", "do_nothing", "analyst"):
        kw = {"threshold": study["analyst_threshold"]} if name == "analyst" else {}
        res["baselines"][name] = _baseline_eval(name, "heldout", seeds, **kw)
    write_json(run_dir(profile) / "heldout.json", res)
    if profile == "full" and not first.exists():
        write_json(first, {"recorded_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "spec_sha256": sha, "episodes": len(seeds), **res})
        log("held-out first run recorded")
    for k, v in {**res["policies"], **res["baselines"]}.items():
        log(f"held-out {k}: robust reward {v['reward']:+.3f}, contained {v['contained']:.2f}, innocent isolated {v['benign_isolated']:.2f}")
    return res
