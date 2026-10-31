"""The whole run, step by step. Full-profile outputs are committed: models/, reports/, docs/REPORT.md."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import numpy as np

from .. import config


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def run_dir(profile: str) -> Path:
    d = config.ROOT / "runs" / profile
    d.mkdir(parents=True, exist_ok=True)
    return d


def prof(profile: str) -> dict[str, Any]:
    return config.load("experiment")["profiles"][profile]


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=1, default=lambda o: o.item() if hasattr(o, "item") else str(o)))


# ---------------------------------------------------------------------- steps
def step_study(profile: str) -> dict[str, Any]:
    from .grader_study import run_study

    res = run_study(prof(profile)["tasks_per_class"], workers=config.load("experiment")["workers"], log=log)
    write_json(run_dir(profile) / "grader_study.json", res)
    return res


def step_redteam(profile: str) -> dict[str, Any]:
    from .redteam import files_present, grade_redteam

    out = {}
    for name in config.load("patch")["redteam"]["sets"]:
        if not files_present(name):
            log(f"{name}: no patches yet")
            continue
        res = grade_redteam(name, log=log)
        out[name] = res
        first = config.ROOT / "reports" / "heldout" / f"{name}_first_run.json"
        if profile == "full" and not first.exists():  # a blind set's first grading is kept as it was (AGENTS.md: held-out rule)
            write_json(first, {"recorded_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **res})
            log(f"{name}: first run recorded")
    write_json(run_dir(profile) / "redteam.json", out)
    return out


def step_rl(profile: str) -> dict[str, Any]:
    from .rl_study import run_rl_study

    return run_rl_study(str(run_dir(profile) / "rl"), workers=config.load("experiment")["workers"], log=log,
                        overrides=prof(profile).get("rl"))


def step_heldout(profile: str) -> dict[str, Any]:
    from .heldout import run_heldout

    return run_heldout(profile, log=log)


def step_bench(profile: str) -> dict[str, Any]:
    from .bench import bench

    res = bench(prof(profile)["bench_episodes"])
    write_json(run_dir(profile) / "bench.json", res)
    log(f"throughput: {res}")
    return res


def step_transcripts(profile: str) -> dict[str, Any]:
    from ..harness.demo import demo_transcripts

    path = run_dir(profile) / "transcripts.jsonl"
    path.unlink(missing_ok=True)
    res = demo_transcripts(path)
    log(f"transcripts: {res}")
    return res


def step_report(profile: str) -> None:
    from .report import write_reports

    write_reports(profile)


def step_gate(profile: str) -> bool:
    from .gate import gate

    return gate(profile)


STEPS = {"study": step_study, "redteam": step_redteam, "rl": step_rl, "heldout": step_heldout, "bench": step_bench,
         "transcripts": step_transcripts, "report": step_report, "gate": step_gate}
ORDER = ("study", "redteam", "rl", "heldout", "bench", "transcripts", "report")


def run_all(profile: str) -> bool:
    for name in ORDER:
        t = time.time()
        STEPS[name](profile)
        log(f"step {name} done in {time.time() - t:.0f}s")
    return step_gate(profile)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def mean(xs: list[float]) -> float:
    return float(np.mean(xs)) if xs else float("nan")
