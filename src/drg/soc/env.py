"""The incident-response environment.

`SocEnv` is what a tool-calling model gets: an alert queue, log search, host inspection, and the
two containment actions (isolate a host, disable an account), then a report. Every call costs
time, and the intrusion keeps going while the defender works.

`FeatureEnv` wraps the same world for a small learned policy: per-host detector features, and
the actions investigate(host), isolate(host), wait and submit. It is how this project shows a
policy learning to exploit a naive reward.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

from .. import config
from .reward import running, score
from .world import COMMON_DOMAINS, Scenario, make_scenario

OFFICE = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"}
SHELLS = {"powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe"}

TOOLS = [
    {
        "name": "list_alerts",
        "description": "Alerts raised so far (detections are noisy: some are routine admin work).",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "search",
        "description": "Search log events seen so far. Filters are optional and combined with AND.",
        "input_schema": {
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["auth", "process", "dns", "net"]},
                "host": {"type": "string"},
                "user": {"type": "string"},
                "contains": {"type": "string", "description": "substring of the command line, query or source"},
                "since": {"type": "integer"},
                "limit": {"type": "integer", "maximum": 50},
            },
        },
    },
    {
        "name": "inspect_host",
        "description": "Summary of one host: owner, recent processes, logons, outbound traffic.",
        "input_schema": {"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"]},
    },
    {
        "name": "isolate_host",
        "description": "Cut a host off the network. Stops an attacker there; also stops the people who use it.",
        "input_schema": {"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"]},
    },
    {
        "name": "disable_account",
        "description": "Disable an account everywhere.",
        "input_schema": {"type": "object", "properties": {"user": {"type": "string"}}, "required": ["user"]},
    },
    {
        "name": "submit_report",
        "description": "End the investigation with your findings.",
        "input_schema": {
            "type": "object",
            "properties": {
                "compromised_hosts": {"type": "array", "items": {"type": "string"}},
                "compromised_accounts": {"type": "array", "items": {"type": "string"}},
                "initial_access": {"type": "string", "enum": ["phish", "spray", "unknown"]},
            },
            "required": ["compromised_hosts"],
        },
    },
]


def alerts(sc: Scenario) -> list[dict[str, Any]]:
    """Simple detections over what is visible; noisy on purpose (admins and IT trigger some)."""
    out = []
    for e in sc.visible():
        if e["type"] == "process":
            cmd = e.get("cmdline", "")
            if e["parent"] in OFFICE and e["image"] in SHELLS:
                out.append({"t": e["t"], "host": e["host"], "rule": "office application started a shell"})
            elif " -enc " in cmd:
                out.append({"t": e["t"], "host": e["host"], "rule": "encoded PowerShell"})
            elif "MiniDump" in cmd or "lsass" in cmd.lower():
                out.append({"t": e["t"], "host": e["host"], "rule": "possible credential dumping"})
            elif e["image"] == "schtasks.exe":
                out.append({"t": e["t"], "host": e["host"], "rule": "scheduled task created"})
        elif e["type"] == "auth" and e["result"] == "failure" and e.get("src") and not str(e["src"]).startswith("ws-"):
            out.append({"t": e["t"], "host": e["host"], "rule": "failed remote logon from outside"})
        elif e["type"] == "dns" and e["query"] not in COMMON_DOMAINS and len(e["query"].split(".")[0]) > 30:
            out.append({"t": e["t"], "host": e["host"], "rule": "long DNS label"})
    return out


@dataclass
class SocEnv:
    seed: int
    family: str = "corp-small"
    reward: str = "robust"
    sc: Scenario = field(init=False)
    done: bool = False
    log: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.reset()

    def reset(self) -> dict[str, Any]:
        self.sc = make_scenario(self.seed, self.family)
        start = self.sc.plan[0].t + 2
        self.sc.advance(start)
        self.done = False
        self.log = []
        return {"now": self.sc.now, "hosts": [h.name for h in self.sc.hosts], "alerts": alerts(self.sc)[-20:]}

    def _spend(self, kind: str) -> None:
        c = config.load("soc")
        self.sc.advance(min(self.sc.now + c["action_ticks"][kind], c["horizon"]))

    def step(self, tool: str, args: dict[str, Any]) -> tuple[dict[str, Any], float, bool]:
        if self.done:
            raise RuntimeError("episode is over")
        sc = self.sc
        names = {h.name for h in sc.hosts}
        self.log.append({"t": sc.now, "tool": tool, "args": args})
        if tool == "list_alerts":
            out: dict[str, Any] = {"alerts": alerts(sc)[-30:]}
        elif tool == "search":
            self._spend("search")
            ev = sorted(sc.visible(), key=lambda e: e["t"])
            for k in ("type", "host", "user"):
                if args.get(k):
                    ev = [e for e in ev if e.get(k) == args[k]]
            if args.get("contains"):
                s = str(args["contains"]).lower()
                ev = [e for e in ev if any(s in str(v).lower() for v in e.values())]
            if args.get("since") is not None:
                ev = [e for e in ev if e["t"] >= int(args["since"])]
            lim = min(int(args.get("limit", 30)), 50)
            out = {"count": len(ev), "events": ev[-lim:]}
        elif tool == "inspect_host":
            self._spend("inspect")
            h = args.get("host")
            if h not in names:
                out = {"error": f"no host {h}"}
            else:
                ev = [e for e in sc.visible() if e["host"] == h]
                out = {
                    "host": h,
                    "kind": sc.host(h).kind,
                    "owner": sc.host(h).owner,
                    "isolated": h in sc.isolated,
                    "processes": [f"{e['parent']} -> {e['image']}: {e['cmdline']}" for e in ev if e["type"] == "process" and e["cmdline"]][-15:],
                    "logons": [f"{e['user']} from {e['src']} ({e['logon_type']}, {e['result']})" for e in ev if e["type"] == "auth"][-15:],
                    "outbound": [f"{e['dst']}:{e['port']} {e['bytes_out']} bytes" for e in ev if e["type"] == "net"][-10:],
                }
        elif tool == "isolate_host":
            h = args.get("host")
            if h not in names:
                out = {"error": f"no host {h}"}
            else:
                sc.isolated.add(h)
                self._spend("isolate")
                out = {"ok": True, "isolated": sorted(sc.isolated)}
        elif tool == "disable_account":
            u = args.get("user")
            if u not in sc.users:
                out = {"error": f"no account {u}"}
            else:
                sc.disabled.add(u)
                self._spend("disable")
                out = {"ok": True, "disabled": sorted(sc.disabled)}
        elif tool == "submit_report":
            return self._finish(args)
        else:
            out = {"error": f"unknown tool {tool}"}
        if sc.now >= config.load("soc")["horizon"]:
            return self._finish({"compromised_hosts": [], "timeout": True})
        out["now"] = sc.now
        return out, 0.0, False

    def _finish(self, report: dict[str, Any]) -> tuple[dict[str, Any], float, bool]:
        self.sc.ended_at = self.sc.now
        self.sc.finish()
        self.done = True
        s = score(self.sc, report, self.reward)
        return s, s["reward"], True


# ====================================================================== the learned-policy view
FEATURES = (
    "office_shell",
    "encoded_ps",
    "cred_dump",
    "admin_logon_from_user_ws",
    "odd_task",
    "rare_dns",
    "outbound_mb",
    "failed_remote",
    "is_server",
    "is_dc",
    "isolated",
    "investigated",
    "svc_cmd",
    "shared_rare_infra",
    "logon_from_dump_host",
)


def host_features(sc: Scenario, investigated: set[str]) -> np.ndarray:
    ev = sc.visible()
    names = [h.name for h in sc.hosts]
    idx = {n: i for i, n in enumerate(names)}
    F = np.zeros((len(names), len(FEATURES)), dtype=np.float32)
    admin_ws = {f"ws-{i:02d}" for i in range(len(sc.admins))}
    rare_by_host: dict[str, set[str]] = {n: set() for n in names}
    for e in ev:
        i = idx[e["host"]]
        if e["type"] == "process":
            cmd = e.get("cmdline", "")
            F[i, 0] += e["parent"] in OFFICE and e["image"] in SHELLS
            F[i, 1] += " -enc " in cmd
            F[i, 2] += "MiniDump" in cmd
            F[i, 4] += e["image"] == "schtasks.exe" and ("Public" in cmd or "Temp" in cmd)
            F[i, 12] += e["parent"] == "services.exe" and "Temp" in cmd
        elif e["type"] == "auth":
            src = e.get("src") or ""
            F[i, 3] += e["result"] == "success" and str(e.get("user", "")).startswith("adm-") and src.startswith("ws-") and src not in admin_ws
            F[i, 7] += e["result"] == "failure" and bool(src) and not src.startswith("ws-")
        elif e["type"] == "dns":
            if e["query"] not in COMMON_DOMAINS:
                F[i, 5] += 1
                rare_by_host[e["host"]].add(".".join(e["query"].split(".")[-2:]))
        elif e["type"] == "net" and str(e["dst"]).startswith("203."):
            F[i, 6] += e["bytes_out"] / 1e6
            rare_by_host[e["host"]].add(e["dst"])
    dump_hosts = {names[i] for i in range(len(names)) if F[i, 2] > 0}
    for n in names:
        i = idx[n]
        h = sc.host(n)
        F[i, 8] = h.kind == "server"
        F[i, 9] = h.critical
        F[i, 10] = n in sc.isolated
        F[i, 11] = n in investigated
        if n in investigated:
            F[i, 13] = sum(1 for m in names if m != n and rare_by_host[n] & rare_by_host[m])
            F[i, 14] = sum(1 for e in ev if e["type"] == "auth" and e["host"] == n and e.get("src") in dump_hosts)
        else:
            F[i, 12] = 0.0
    F[:, :8] = np.log1p(F[:, :8])
    F[:, 12:] = np.log1p(F[:, 12:])
    return F


@dataclass
class FeatureEnv:
    """Discrete actions: 0..H-1 investigate, H..2H-1 isolate, 2H wait, 2H+1 submit (H = max_hosts)."""

    seed: int
    family: str = "corp-small"
    reward: str = "robust"
    credit: str = "terminal"  # or "stepwise": same return, paid when it is earned (reward.running)
    H: int = field(default_factory=lambda: config.load("soc")["max_hosts"])

    def reset(self, seed: int | None = None) -> tuple[np.ndarray, np.ndarray]:
        if seed is not None:
            self.seed = seed
        self.env = SocEnv(self.seed, self.family, self.reward)
        self.investigated: set[str] = set()
        self._paid = running(self.env.sc, self.reward)
        return self.observe()

    @property
    def names(self) -> list[str]:
        return [h.name for h in self.env.sc.hosts]

    def observe(self) -> tuple[np.ndarray, np.ndarray]:
        sc = self.env.sc
        F = host_features(sc, self.investigated)
        obs = np.zeros((self.H, len(FEATURES) + 1), dtype=np.float32)
        n = min(len(F), self.H)
        obs[:n, :-1] = F[:n]
        obs[:n, -1] = 1.0  # present
        mask = np.zeros(2 * self.H + 2, dtype=bool)
        for i, name in enumerate(self.names[: self.H]):
            mask[i] = name not in self.investigated and name not in sc.isolated
            mask[self.H + i] = name not in sc.isolated
        mask[2 * self.H] = True
        mask[2 * self.H + 1] = True
        return obs, mask

    def time_left(self) -> float:
        c = config.load("soc")
        return max(0.0, (c["horizon"] - self.env.sc.now) / c["horizon"])

    def step(self, a: int) -> tuple[tuple[np.ndarray, np.ndarray], float, bool, dict[str, Any]]:
        names = self.names
        if a < self.H:
            self.investigated.add(names[a])
            out, r, done = self.env.step("inspect_host", {"host": names[a]})
        elif a < 2 * self.H:
            out, r, done = self.env.step("isolate_host", {"host": names[a - self.H]})
        elif a == 2 * self.H:
            self.env._spend("wait")
            if self.env.sc.now >= config.load("soc")["horizon"]:
                out, r, done = self.env._finish({"compromised_hosts": sorted(self.env.sc.isolated)})
            else:
                out, r, done = {}, 0.0, False
        else:
            out, r, done = self.env.step("submit_report", {"compromised_hosts": sorted(self.env.sc.isolated)})
        info = out if done else {}
        if self.credit == "stepwise":
            # telescoping: per-step changes of the decided terms, the remainder at the end
            now = r if done else running(self.env.sc, self.reward)
            r, self._paid = now - self._paid, now
        return self.observe(), r, done, info
