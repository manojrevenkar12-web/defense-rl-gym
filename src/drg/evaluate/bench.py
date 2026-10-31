"""Environment throughput on one core: what a training cluster can expect per worker."""

from __future__ import annotations

import time
from typing import Any

from ..patch.grader import grade
from ..patch.task import make_task
from ..soc import baselines


def bench(n: int) -> dict[str, Any]:
    t = time.perf_counter()
    for s in range(n):
        baselines.run(baselines.analyst, 6_500_000 + s, "corp-small", "robust")
    soc = (time.perf_counter() - t) / n
    t = time.perf_counter()
    for s in range(n):
        task = make_task(6_000_000 + s)
        grade(task, task.source("ref"), "robust")
    patch = (time.perf_counter() - t) / n
    return {"soc_episode_s": float(soc), "soc_episodes_per_s": float(1 / soc), "patch_grade_s": float(patch),
            "patch_grades_per_s": float(1 / patch), "n": n, "cores": 1, "note": "analyst policy, robust grader with fresh reference run"}
