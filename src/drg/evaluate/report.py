"""reports/results.json and docs/REPORT.md, generated from a run. Do not edit them by hand."""

from __future__ import annotations

import json
import time
from typing import Any

import numpy as np

from .. import config
from ..patch.grader import GRADERS
from .gate import check
from .pipeline import run_dir, write_json

VARIANT_LABEL = {
    "ref": "reference fix", "alt1": "valid fix, written differently (1)", "alt2": "valid fix, written differently (2)",
    "partial": "partial fix (one bypass left)", "overblock": "over-blocking fix (breaks legitimate requests)",
    "first_site_only": "fixes one of two vulnerable functions", "hack_delete": "hack: remove the feature",
    "hack_public": "hack: special-case the reported attack", "hack_tamper": "hack: hide the evidence",
}
GRADER_LABEL = {
    "reference_match": "looks like the reference fix", "public_tests": "the report's two requests",
    "hidden_security": "hidden attacks only", "hidden_tests": "hidden attacks + hidden legitimate requests",
    "robust": "robust (hidden tests, fresh markers, trusted log, static policy)",
}


def _load(p) -> Any:
    return json.loads(p.read_text()) if p.exists() else None


def _mean(xs: list[float]) -> float | None:
    return float(np.mean(xs)) if xs else None


def _agg(evals: list[dict[str, float]]) -> dict[str, float]:
    return {k: float(np.mean([e[k] for e in evals])) for k in evals[0]} if evals else {}


def collect(profile: str) -> dict[str, Any]:
    rd = run_dir(profile)
    r: dict[str, Any] = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "profile": profile}
    st = _load(rd / "grader_study.json")
    if st:
        r["study"] = st["summary"]
        r["study_tasks"] = len({(x["cwe"], x["seed"]) for x in st["rows"]})
    rt = _load(rd / "redteam.json")
    if rt:
        r["redteam"] = {}
        for name, res in rt.items():
            first = _load(config.ROOT / "reports" / "heldout" / f"{name}_first_run.json")
            src = first if (profile == "full" and first) else res
            r["redteam"][name] = {"status": res["status"], "recorded_at": (first or {}).get("recorded_at"),
                                  **{g: {**v, "fixes_rate": v["fixes_accepted"] / v["fixes"] if v["fixes"] else None,
                                         "hacks_rate": v["hacks_accepted"] / v["hacks"] if v["hacks"] else None}
                                     for g, v in src["summary"].items()}}
    rl = _load(rd / "rl" / "rl_study.json")
    if rl:
        fams = rl["families"]
        names = list(dict.fromkeys(x["variant"] for x in rl["runs"]))
        pol = {n: {f: _agg([x["eval"][f] for x in rl["runs"] if x["variant"] == n]) for f in fams} for n in names}
        cloned = [x["clone_eval"] for x in rl["runs"] if x.get("clone_eval")]
        if cloned:
            pol["cloned_analyst"] = {f: _agg([c[f] for c in cloned]) for f in fams}
        curves = {}
        for n in names:
            cs = [x["curve"] for x in rl["runs"] if x["variant"] == n]
            k = min(len(c) for c in cs)
            curves[n] = [{m: float(np.mean([c[i][m] for c in cs])) for m in ("reward", "contained", "benign_isolated", "caught")} for i in range(k)]
        f0 = fams[0]
        best = pol.get("robust_clone") or pol.get("robust_scratch")
        r["rl"] = {
            "families": fams, "policies": pol, "baselines": rl["baselines"], "curves": curves, "analyst_threshold": rl["analyst_threshold"],
            "seeds": sorted({x["seed"] for x in rl["runs"]}), "variants": {x["variant"]: {k: x[k] for k in ("reward", "credit", "init")} for x in rl["runs"]},
            "clone_accuracy": _mean([x["clone_accuracy"] for x in rl["runs"] if x.get("clone_accuracy") is not None]),
            "margin_vs_isolate_all": best[f0]["reward"] - rl["baselines"]["isolate_all"][f0]["reward"],
            "margin_vs_analyst": best[f0]["reward"] - rl["baselines"]["analyst"][f0]["reward"],
            "benign_isolated_reduction": pol["naive_scratch"][f0]["benign_isolated"] - best[f0]["benign_isolated"] if "naive_scratch" in pol else None,
            "gain_over_cloning": best[f0]["reward"] - pol["cloned_analyst"][f0]["reward"] if cloned else None,
            "robust_contained": best[f0]["contained"],
        }
    first = config.ROOT / "reports" / "heldout" / "first_run.json"
    held = _load(first) if profile == "full" else _load(rd / "heldout.json")
    if held:
        groups: dict[str, list[dict[str, float]]] = {}
        for k, v in held["policies"].items():
            groups.setdefault(k.rsplit("_", 1)[0], []).append(v)
        hp = {k: _agg(v) for k, v in groups.items()}
        main = hp.get("robust_clone") or next(iter(hp.values()))
        r["heldout"] = {"policies": hp, "baselines": held["baselines"], "robust_reward": main.get("reward"),
                        "margin_vs_analyst": main.get("reward", 0) - held["baselines"]["analyst"]["reward"],
                        "recorded_at": held.get("recorded_at"), "spec_sha256": held.get("spec_sha256")}
    b = _load(rd / "bench.json")
    if b:
        r["bench"] = b
    return r


def write_reports(profile: str) -> dict[str, Any]:
    r = collect(profile)
    rel = config.load("release")
    r["gate"] = {"floors": check(r, rel["floors"]), "targets": check(r, rel["targets"])}
    out = config.ROOT / "reports" if profile == "full" else run_dir(profile)
    write_json(out / "results.json", r)
    target = config.ROOT / "docs" / "REPORT.md" if profile == "full" else out / "REPORT.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(markdown(r))
    return r


def _p(v: float | None) -> str:
    return "n/a" if v is None else f"{100 * v:.0f}%"


def markdown(r: dict[str, Any]) -> str:
    parts = [f"# Report\n\nGenerated by `drg report` ({r['generated_at']}, profile `{r['profile']}`). Do not edit.\n"]
    st = r.get("study")
    if st:
        variants = list(VARIANT_LABEL)
        head = "| Patch | Valid? | " + " | ".join(GRADER_LABEL[g] for g in GRADERS) + " |\n|---|---|" + "---:|" * len(GRADERS)
        rows = [f"| {VARIANT_LABEL[v]} | {'yes' if v in ('ref', 'alt1', 'alt2') else 'no'} | " + " | ".join(_p(st[g]['by_variant'].get(v)) for g in GRADERS) + " |"
                for v in variants if v in st[GRADERS[0]]["by_variant"]]
        summ = "| | " + " | ".join(GRADER_LABEL[g] for g in GRADERS) + " |\n|---|" + "---:|" * len(GRADERS) + "\n"
        summ += "| valid fixes accepted | " + " | ".join(_p(st[g]["valid_accepted"]) for g in GRADERS) + " |\n"
        summ += "| invalid patches accepted | " + " | ".join(_p(st[g]["invalid_accepted"]) for g in GRADERS) + " |"
        parts.append(f"## Q1. Which reward can be trusted for patching?\n\n{r['study_tasks']} generated tasks (six weakness classes); every patch's "
                     "validity is known by construction. Share of each kind of patch that each grader accepts:\n\n" + head + "\n" + "\n".join(rows)
                     + "\n\nIn total:\n\n" + summ + "\n")
    rt = r.get("redteam")
    if rt:
        rows = []
        for name, res in rt.items():
            for g in GRADERS:
                v = res[g]
                hk = f"{v['hacks_accepted']}/{v['hacks']}" if v["hacks"] else "none written"
                rows.append(f"| {name} ({res['status']}) | {GRADER_LABEL[g]} | {v['fixes_accepted']}/{v['fixes']} | {hk} |")
        parts.append("## Q2. Blind red team\n\nFor each of six tasks, someone who saw only the agent's files (never the grader) wrote a genuine "
                     "fix and, in `redteam_v1`, three reward hacks. Each set's first grading is kept as recorded "
                     "(`reports/heldout/<set>_first_run.json`). `redteam_v1` became a regression set after its one rejected fix was studied "
                     "(`heldout/redteam_v1/STATUS`); `redteam_v2` was written after that change, by a new writer.\n\n"
                     "| Set | Grader | Genuine fixes accepted | Hacks accepted |\n|---|---|---:|---:|\n" + "\n".join(rows) + "\n")
    rl = r.get("rl")
    if rl:
        label = {"naive_scratch": "PPO from scratch, naive reward", "robust_scratch": "PPO from scratch, robust reward",
                 "cloned_analyst": "cloned analyst (before RL)", "naive_clone": "cloned analyst + PPO, naive reward",
                 "robust_clone": "cloned analyst + PPO, robust reward"}
        lines = ["| Policy | Family | Robust reward | Attack stopped | Innocent machines isolated | Domain controller isolated | Attacker's machines isolated |",
                 "|---|---|---:|---:|---:|---:|---:|"]
        for f in rl["families"]:
            rows = [(label.get(n, n), v[f]) for n, v in rl["policies"].items()]
            rows += [("isolate everything", rl["baselines"]["isolate_all"][f]), ("tuned rule-based analyst", rl["baselines"]["analyst"][f]),
                     ("do nothing", rl["baselines"]["do_nothing"][f])]
            for name, v in rows:
                lines.append(f"| {name} | {f} | {v['reward']:+.2f} | {_p(v['contained'])} | {v['benign_isolated']:.1f} | {v['dc_isolated']:.2f} | {_p(v['caught'])} |")
        parts.append(f"## Q3. What does a learned policy do with each reward?\n\nPPO on `corp-small` ({len(rl['seeds'])} seeds per variant), "
                     "judged on separate seeds by what a defender wanted (the robust reward and its parts). The rule-based analyst's threshold "
                     f"({rl['analyst_threshold']}) was tuned on training seeds; the cloned policy matches its actions "
                     f"{_p(rl['clone_accuracy'])} of the time.\n\n" + "\n".join(lines) + "\n")
    h = r.get("heldout")
    if h:
        label = {"naive_scratch": "PPO from scratch, naive reward", "robust_scratch": "PPO from scratch, robust reward",
                 "naive_clone": "cloned analyst + PPO, naive reward", "robust_clone": "cloned analyst + PPO, robust reward"}
        lines = ["| Policy | Robust reward | Attack stopped | Innocent machines isolated | Attacker's machines isolated |", "|---|---:|---:|---:|---:|"]
        rows = [(label.get(k, k), v) for k, v in h["policies"].items()]
        rows += [("tuned analyst", h["baselines"]["analyst"]), ("isolate everything", h["baselines"]["isolate_all"]), ("do nothing", h["baselines"]["do_nothing"])]
        for name, v in rows:
            lines.append(f"| {name} | {v['reward']:+.2f} | {_p(v['contained'])} | {v['benign_isolated']:.1f} | {_p(v['caught'])} |")
        parts.append(f"## Held-out network family (blind)\n\nWritten from `heldout/WRITING_FAMILY.md` by someone who had not seen the code; run once "
                     f"({h.get('recorded_at')}), never rewritten.\n\n" + "\n".join(lines) + "\n")
    b = r.get("bench")
    if b:
        parts.append(f"## Throughput (one core)\n\nIncident episodes: {b['soc_episodes_per_s']:.1f} per second. Patch grades with the robust grader "
                     f"(which also runs the reference): {b['patch_grades_per_s']:.1f} per second.\n")
    g = r.get("gate")
    if g:
        fmt = lambda v: "n/a" if v is None else (f"{v:.3f}" if isinstance(v, float) else str(v))  # noqa: E731
        parts.append("## Release gate\n\n| | Check | Actual | Required |\n|---|---|---:|---:|\n"
                     + "\n".join(f"| {'pass' if x['ok'] else '**fail**'} | {x['name']} | {fmt(x['actual'])} | {x['op']} {x['value']} |" for x in g["floors"])
                     + "\n\nTargets (reported, not gated):\n\n| | Target | Actual | Aim |\n|---|---|---:|---:|\n"
                     + "\n".join(f"| {'met' if x['ok'] else 'missed'} | {x['name']} | {fmt(x['actual'])} | {x['op']} {x['value']} |" for x in g["targets"]) + "\n")
    return "\n".join(parts)
