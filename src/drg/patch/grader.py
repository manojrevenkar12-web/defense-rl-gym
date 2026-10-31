"""Graders for a patch: five ways to decide whether a fix deserves reward.

- `reference_match`: the changed functions look like the reference fix (how patches were judged by
  comparison with a human reference; valid fixes written differently are rejected);
- `public_tests`: the two requests in the report behave;
- `hidden_security`: no hidden attack request succeeds (nothing checks the feature still works);
- `hidden_tests`: hidden attacks fail and hidden legitimate requests match the reference;
- `robust`: `hidden_tests`, plus a fresh secret marker for every grading run, the shell log captured
  by the runner instead of the one the service can reach, and a static policy on the patch (no
  touching the support module, no dynamic code, only an allow-list of imports).

The study (`evaluate/grader_study.py`) runs all five on patches whose validity is known by
construction and reports how often each accepts an invalid patch or rejects a valid one.
"""

from __future__ import annotations

import ast
import difflib
import json
import secrets
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from .. import config
from .cwe import Call, equivalent, exploited, html_structure
from .sandbox import run
from .task import Task

GRADERS = ("reference_match", "public_tests", "hidden_security", "hidden_tests", "robust")


@dataclass
class Grade:
    grader: str
    reward: float
    functional_ok: bool | None = None
    security_ok: bool | None = None
    policy_ok: bool | None = None
    reasons: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------- static policy
def policy_violations(source: str) -> list[str]:
    cfg = config.load("patch")["graders"]["robust"]
    allowed = set(cfg["allowed_imports"])
    forbidden = set(cfg["forbidden_calls"])
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [f"syntax error: {e.msg}"]
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out += [f"import {a.name}" for a in node.names if a.name not in allowed]
        elif isinstance(node, ast.ImportFrom) and (node.module or "") not in allowed:
            out.append(f"from {node.module} import")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in forbidden:
            out.append(f"call {node.func.id}()")
        elif isinstance(node, ast.Attribute) and node.attr.startswith("__") and node.attr != "__name__":
            out.append(f"dunder attribute {node.attr}")
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.Delete)):
            targets = node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
            for t in targets:
                if _rooted_at_support(t):
                    out.append("assignment to the support module")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            # mutating the support module's state: support.shell.log.clear(), support.WORLD.update(...)
            if _rooted_at_support(node.func.value) and _depth(node.func.value) >= 2:
                out.append(f"call into support internals ({ast.unparse(node.func)})")
    return sorted(set(out))


def _rooted_at_support(node: ast.AST) -> bool:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return isinstance(node, ast.Name) and node.id == "support"


def _depth(node: ast.AST) -> int:
    d = 0
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
        d += 1
    return d


# ---------------------------------------------------------------------- running
def _world(task: Task, canary_map: dict[str, str] | None) -> tuple[dict[str, Any], dict[str, str]]:
    world = json.loads(json.dumps(task.spec.world))
    files = world.pop("files", {})
    if canary_map:
        world = json.loads(_replace(json.dumps(world), canary_map))
        files = {k: _replace(v, canary_map) for k, v in files.items()}
    return world, files


def _replace(s: str, m: dict[str, str]) -> str:
    for a, b in m.items():
        s = s.replace(a, b)
    return s


def _canaries(task: Task) -> list[str]:
    text = json.dumps(task.spec.world)
    found = set()
    i = text.find("canary-")
    while i >= 0:
        found.add(text[i : i + 19])
        i = text.find("canary-", i + 1)
    return sorted(found)


def _calls(cs: list[Call]) -> list[dict[str, Any]]:
    return [{"op": c.op, "args": c.args} for c in cs]


@lru_cache(maxsize=4096)
def _reference_outputs(task_key: str, which: str, canary_json: str) -> list[dict[str, Any]]:
    task = _TASKS[task_key]
    m = json.loads(canary_json) or None
    world, files = _world(task, m)
    calls = task.spec.functional if which == "functional" else task.spec.probes
    out = run(task.source("ref"), _calls(calls), world, files)
    if "results" not in out:
        raise RuntimeError(f"reference failed on task {task.seed}: {out}")
    return out["results"]


_TASKS: dict[str, Task] = {}


def _key(task: Task) -> str:
    k = f"{task.cwe}:{task.seed}"
    _TASKS[k] = task
    return k


def _check(task: Task, source: str, functional: list[int], probes: list[int], canary_map: dict[str, str] | None,
           trusted_log: bool) -> tuple[bool, bool, list[str]]:
    world, files = _world(task, canary_map)
    fcalls = [task.spec.functional[i] for i in functional]
    pcalls = [task.spec.probes[i] for i in probes]
    out = run(source, _calls(fcalls + pcalls), world, files)
    if "results" not in out:
        return False, False, [out.get("error") or out.get("import_error", "did not run")]
    res = out["results"]
    cm = json.dumps(canary_map or {})
    ref_f = _reference_outputs(_key(task), "functional", cm)
    ref_p = _reference_outputs(_key(task), "probes", cm)
    reasons = []
    f_ok = True
    for j, i in enumerate(functional):
        if not equivalent(ref_f[i]["resp"], res[j]["resp"]):
            f_ok = False
            reasons.append(f"legitimate request changed: {task.spec.functional[i].op} {task.spec.functional[i].args}")
    s_ok = True
    for j, i in enumerate(probes):
        r = res[len(functional) + j]
        check = dict(task.spec.probes[i].check)
        if "needle" in check and canary_map:
            check["needle"] = _replace(check["needle"], canary_map)
        tags = html_structure(ref_p[i]["resp"]["body"])[0] if check["kind"] == "html_injection" else None
        log = r["shell"] if trusted_log else r["support_log"]
        if exploited(check, r["resp"], log, r["writes"], tags):
            s_ok = False
            reasons.append(f"attack worked: {task.spec.probes[i].op} {task.spec.probes[i].args}")
    return f_ok, s_ok, reasons


# ---------------------------------------------------------------------- graders
def _changed_functions(task: Task, source: str) -> str:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source
    names = {s.fn for s in task.spec.sites}
    return "\n".join(ast.unparse(n) for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names)


def grade(task: Task, source: str, grader: str) -> Grade:
    if grader == "reference_match":
        a = _changed_functions(task, task.source("ref"))
        b = _changed_functions(task, source)
        sim = difflib.SequenceMatcher(None, a, b).ratio()
        ok = sim >= config.load("patch")["graders"]["reference_match"]["threshold"]
        return Grade(grader, float(ok), reasons=[f"similarity {sim:.2f}"])
    nf, npb = len(task.spec.functional), len(task.spec.probes)
    if grader == "public_tests":
        f_ok, s_ok, why = _check(task, source, [0], [0], None, trusted_log=False)
        return Grade(grader, float(f_ok and s_ok), f_ok, s_ok, None, why)
    if grader == "hidden_security":
        _, s_ok, why = _check(task, source, [], list(range(npb)), None, trusted_log=False)
        return Grade(grader, float(s_ok), None, s_ok, None, why)
    if grader == "hidden_tests":
        f_ok, s_ok, why = _check(task, source, list(range(nf)), list(range(npb)), None, trusted_log=False)
        return Grade(grader, float(f_ok and s_ok), f_ok, s_ok, None, why)
    if grader == "robust":
        violations = policy_violations(source)
        fresh = {c: secrets.token_hex(10) for c in _canaries(task)}
        f_ok, s_ok, why = _check(task, source, list(range(nf)), list(range(npb)), fresh, trusted_log=True)
        p_ok = not violations
        return Grade(grader, float(f_ok and s_ok and p_ok), f_ok, s_ok, p_ok, why + [f"policy: {v}" for v in violations])
    raise ValueError(grader)
