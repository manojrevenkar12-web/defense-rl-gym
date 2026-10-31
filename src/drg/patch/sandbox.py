"""Run a service source on a batch of requests in a separate, limited process."""

from __future__ import annotations

import json
import os
import resource
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .. import config

RUNNER = Path(__file__).with_name("runner.py")
SUPPORT = Path(__file__).with_name("support.py")


def _limits() -> None:
    lim = config.load("patch")["sandbox"]
    mb = 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (lim["memory_mb"] * mb, lim["memory_mb"] * mb))
    resource.setrlimit(resource.RLIMIT_CPU, (lim["cpu_s"], lim["cpu_s"]))
    resource.setrlimit(resource.RLIMIT_FSIZE, (lim["file_mb"] * mb, lim["file_mb"] * mb))
    os.setsid()


def run(source: str, calls: list[dict[str, Any]], world: dict[str, Any], files: dict[str, str]) -> dict[str, Any]:
    """Execute `source` as service.py on `calls`. Returns {"results": [...]} or an error."""
    lim = config.load("patch")["sandbox"]
    with tempfile.TemporaryDirectory(prefix="drg-") as tmp:
        work = Path(tmp) / "work"
        root = Path(tmp) / "root"
        work.mkdir()
        root.mkdir()
        (work / "service.py").write_text(source)
        (work / "support.py").write_text(SUPPORT.read_text())  # always the original
        env = {"DRG_ROOT": str(root), "PATH": "/usr/bin:/bin", "PYTHONHASHSEED": "0", "LANG": "C.UTF-8"}
        job = json.dumps({"calls": calls, "world": world, "files": files})
        try:
            p = subprocess.run(
                [sys.executable, "-I", "-S", str(RUNNER), str(work)],
                input=job,
                capture_output=True,
                text=True,
                timeout=lim["wall_s"],
                env=env,
                cwd=tmp,
                preexec_fn=_limits,
            )
        except subprocess.TimeoutExpired:
            return {"error": "timeout"}
        if p.returncode != 0 or not p.stdout.strip():
            return {"error": f"exit {p.returncode}: {p.stderr[-400:]}"}
        try:
            out = json.loads(p.stdout.strip().splitlines()[-1])
        except json.JSONDecodeError:
            return {"error": "unreadable runner output"}
        out["root"] = str(root)
        return out
