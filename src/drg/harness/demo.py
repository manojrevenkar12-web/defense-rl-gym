"""Example transcripts in the training-data format, from scripted (replay) models: no network.

For the patch environment the script reads the report, writes the reference fix and submits (and,
as a contrast, submits the evidence-hiding hack); for the incident environment an oracle script
that knows the answer lists alerts, searches, inspects, isolates and reports. They show the format
and exercise the whole loop; they are not a model's work.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..patch.task import make_task
from ..soc.env import SocEnv
from ..soc.world import truth
from .agent import ReplayModel, run_episode, write_transcripts


def demo_transcripts(path: Path) -> dict[str, Any]:
    eps = []
    for seed in (11, 12):
        t = make_task(seed)
        calls = [
            ("read_file", {"path": "REPORT.md"}),
            ("read_file", {"path": "service.py"}),
            ("run_checks", {}),
            ("write_file", {"path": "service.py", "content": t.source("ref")}),
            ("run_checks", {}),
            ("submit", {}),
        ]
        eps.append(run_episode("patch", seed, ReplayModel(calls)))
        bad = [("write_file", {"path": "service.py", "content": t.source("hack_tamper")}), ("submit", {})]
        eps.append(run_episode("patch", seed, ReplayModel(bad)))
    for seed in (21, 22):
        env = SocEnv(seed)
        tr = truth(env.sc)
        calls = [("list_alerts", {}), ("search", {"type": "process", "contains": "MiniDump"})]
        calls += [("inspect_host", {"host": h}) for h in tr["hosts"]]
        calls += [("isolate_host", {"host": h}) for h in tr["hosts"]]
        calls += [("submit_report", {"compromised_hosts": tr["hosts"], "compromised_accounts": tr["accounts"], "initial_access": tr["initial_access"]})]
        eps.append(run_episode("soc", seed, ReplayModel(calls)))
    write_transcripts(eps, path)
    return {"episodes": len(eps), "rewards": [round(e["reward"], 3) for e in eps]}
