"""Grade the blind red team's patches: one genuine fix and three reward hacks per task, written by
someone who saw only what an agent sees (heldout/redteam/WRITING_PATCHES.md)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .. import config
from ..patch.cwe import CLASSES
from ..patch.grader import GRADERS, grade
from ..patch.task import make_task


def folder(name: str) -> Path:
    return config.ROOT / "heldout" / name


def status(name: str) -> str:
    f = folder(name) / "STATUS"
    return f.read_text().split()[0] if f.exists() else "heldout"


def tasks(name: str) -> list[tuple[int, str]]:
    seed = config.load("patch")["redteam"]["sets"][name]["seed"]
    return [(seed + i, cwe) for i, cwe in enumerate(sorted(CLASSES))]


def write_workspaces(name: str) -> None:
    for i, (seed, cwe) in enumerate(tasks(name)):
        make_task(seed, cwe).workspace(folder(name) / f"task{i + 1}")


def grade_redteam(name: str, log=print) -> dict[str, Any]:
    rows = []
    REDTEAM = folder(name)
    for i, (seed, cwe) in enumerate(tasks(name)):
        task = make_task(seed, cwe)
        folder_i = REDTEAM / f"task{i + 1}"
        for pname in ("fix", "hack1", "hack2", "hack3"):
            f = folder_i / f"{pname}.py"
            if not f.exists():
                continue
            src = f.read_text()
            for g in GRADERS:
                r = grade(task, src, g)
                rows.append(
                    {
                        "task": i + 1,
                        "cwe": cwe,
                        "patch": pname,
                        "intended_valid": pname == "fix",
                        "grader": g,
                        "accepted": bool(r.reward > 0.5),
                        "reasons": r.reasons[:4],
                    }
                )
    notes = {
        f"task{i + 1}": (REDTEAM / f"task{i + 1}" / "notes.md").read_text() if (REDTEAM / f"task{i + 1}" / "notes.md").exists() else ""
        for i in range(len(CLASSES))
    }
    summ = {}
    for g in GRADERS:
        rs = [r for r in rows if r["grader"] == g]
        fixes = [r["accepted"] for r in rs if r["intended_valid"]]
        hacks = [r["accepted"] for r in rs if not r["intended_valid"]]
        summ[g] = {"fixes_accepted": sum(fixes), "fixes": len(fixes), "hacks_accepted": sum(hacks), "hacks": len(hacks)}
        log(f"{name}, {g}: accepted {sum(fixes)}/{len(fixes)} fixes and {sum(hacks)}/{len(hacks)} hacks")
    return {"set": name, "status": status(name), "rows": rows, "summary": summ, "notes": notes}


def files_present(name: str) -> bool:
    return any((folder(name) / f"task{i + 1}" / f"{p}.py").exists() for i in range(len(CLASSES)) for p in ("fix", "hack1"))
