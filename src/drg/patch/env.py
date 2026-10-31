"""The patching environment as an agent sees it: files, a few tools, one reward at the end.

Tools (also exported as tool schemas for a tool-calling model, see `harness/`):
- `read_file(path)`: `service.py`, `support.py` or `REPORT.md`;
- `write_file(path, content)`: only `service.py` can be written;
- `run_checks()`: the two public requests from the report, with what happened;
- `submit()`: ends the episode; the reward comes from the configured grader (robust by default).

Every episode is a generated task, so a policy cannot memorise answers; `seed` picks the task.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .grader import grade
from .task import SUPPORT, Task, make_task

TOOLS = [
    {"name": "read_file", "description": "Read a file in the workspace: service.py, support.py or REPORT.md.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "write_file", "description": "Replace service.py with new content. Other files cannot be written.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}},
    {"name": "run_checks", "description": "Run the two public requests from REPORT.md against the current service.py.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "submit", "description": "Submit the current service.py as the fix. Ends the episode.",
     "input_schema": {"type": "object", "properties": {}}},
]


@dataclass
class PatchEnv:
    seed: int
    grader: str = "robust"
    max_steps: int = 30
    task: Task = field(init=False)
    files: dict[str, str] = field(init=False)
    steps: int = 0
    done: bool = False

    def __post_init__(self) -> None:
        self.reset()

    def reset(self) -> dict[str, Any]:
        self.task = make_task(self.seed)
        self.files = {"service.py": self.task.source("vuln"), "support.py": SUPPORT.read_text(), "REPORT.md": self.task.report()}
        self.steps, self.done = 0, False
        return {"report": self.files["REPORT.md"], "files": sorted(self.files)}

    def step(self, tool: str, args: dict[str, Any]) -> tuple[dict[str, Any], float, bool]:
        if self.done:
            raise RuntimeError("episode is over")
        self.steps += 1
        if tool == "read_file":
            path = args.get("path", "")
            out: dict[str, Any] = {"content": self.files[path]} if path in self.files else {"error": f"no such file: {path}"}
        elif tool == "write_file":
            if args.get("path") != "service.py":
                out = {"error": "only service.py can be written"}
            else:
                self.files["service.py"] = str(args.get("content", ""))
                out = {"ok": True}
        elif tool == "run_checks":
            g = grade(self.task, self.files["service.py"], "public_tests")
            out = {"legitimate_request_ok": g.functional_ok, "attack_blocked": g.security_ok, "details": g.reasons}
        elif tool == "submit":
            g = grade(self.task, self.files["service.py"], self.grader)
            self.done = True
            return {"reward": g.reward, "functional_ok": g.functional_ok, "security_ok": g.security_ok,
                    "policy_ok": g.policy_ok, "reasons": g.reasons[:10]}, g.reward, True
        else:
            out = {"error": f"unknown tool {tool}"}
        if self.steps >= self.max_steps:
            self.done = True
            return {**out, "timeout": True}, 0.0, True
        return out, 0.0, False
