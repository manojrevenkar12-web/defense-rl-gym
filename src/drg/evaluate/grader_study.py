"""How often does each grader reward a bad patch, or refuse a good one?

For every generated task, every variant whose validity is known by construction (three valid fixes
written differently; partial fixes, over-blocking fixes, fixing one site of two; deleting the
feature, special-casing the reported attack, hiding the evidence) is graded by all five graders.
"""

from __future__ import annotations

import time
from multiprocessing import get_context
from typing import Any

import numpy as np

from .. import config
from ..patch.cwe import CLASSES
from ..patch.grader import GRADERS, grade
from ..patch.task import make_task


def _job(args: tuple[str, int]) -> list[dict[str, Any]]:
    cwe, seed = args
    task = make_task(seed, cwe)
    rows = []
    for variant, valid in task.variants().items():
        src = task.source(variant)
        for g in GRADERS:
            r = grade(task, src, g)
            rows.append({"cwe": cwe, "seed": seed, "two_sites": task.two_sites, "variant": variant, "valid": valid,
                         "grader": g, "accepted": bool(r.reward > 0.5)})
    return rows


def run_study(n_per_class: int | None = None, workers: int = 2, log=print) -> dict[str, Any]:
    cfg = config.load("patch")["study"]
    n = n_per_class or cfg["tasks_per_class"]
    jobs = [(cwe, cfg["seed_base"] + i) for cwe in sorted(CLASSES) for i in range(n)]
    t0 = time.time()
    if workers > 1:
        with get_context("spawn").Pool(workers) as pool:
            parts = pool.map(_job, jobs, chunksize=4)
    else:
        parts = [_job(j) for j in jobs]
    rows = [r for p in parts for r in p]
    log(f"grader study: {len(jobs)} tasks, {len(rows)} grades in {time.time() - t0:.0f}s")
    return {"rows": rows, "summary": summarise(rows)}


def _rate(xs: list[bool]) -> float | None:
    return float(np.mean(xs)) if xs else None


def summarise(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    variants = sorted({r["variant"] for r in rows})
    for g in GRADERS:
        rs = [r for r in rows if r["grader"] == g]
        valid = [r["accepted"] for r in rs if r["valid"]]
        invalid = [r["accepted"] for r in rs if not r["valid"]]
        out[g] = {
            "valid_accepted": _rate(valid),
            "invalid_accepted": _rate(invalid),
            "by_variant": {v: _rate([r["accepted"] for r in rs if r["variant"] == v]) for v in variants},
            "by_cwe_invalid_accepted": {c: _rate([r["accepted"] for r in rs if r["cwe"] == c and not r["valid"]]) for c in sorted(CLASSES)},
            "by_cwe_valid_accepted": {c: _rate([r["accepted"] for r in rs if r["cwe"] == c and r["valid"]]) for c in sorted(CLASSES)},
            "n_valid": len(valid),
            "n_invalid": len(invalid),
        }
    return out
