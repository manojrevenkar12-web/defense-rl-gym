"""Scoring an incident-response episode.

`naive` pays for one thing: the attack did not reach exfiltration. That is what a first reward
would check, and it is exploitable: isolating every machine stops every attack. `robust` keeps
that, charges for the business the defender stopped (benign machines isolated, the domain
controller worst of all) and for time, and pays for isolating the machines the attacker actually
held. The report's accuracy is scored separately (`report_*`) and does not enter either reward.
"""

from __future__ import annotations

from typing import Any

from .. import config
from .world import Scenario


def _f1(pred: set[str], true: set[str]) -> float:
    if not pred and not true:
        return 1.0
    tp = len(pred & true)
    if tp == 0:
        return 0.0
    p, r = tp / len(pred), tp / len(true)
    return 2 * p * r / (p + r)


def running(sc: Scenario, kind: str) -> float:
    """The robust reward's terms that are already decided at this moment (everything but `contained`).

    Paying the change in this value at every step and the remainder at the end gives the same
    undiscounted return as paying the whole reward at the end; it only moves credit to the action
    that earned it. The naive reward has no such terms.
    """
    if kind == "naive":
        return 0.0
    r = config.load("soc")["rewards"]["robust"]
    compromised = set(sc.compromised)
    benign_iso = [sc.host(h) for h in sc.isolated if h not in compromised]
    n_ws = sum(1 for h in benign_iso if h.kind == "workstation")
    n_srv = sum(1 for h in benign_iso if h.kind == "server" and not h.critical)
    n_dc = sum(1 for h in benign_iso if h.critical)
    caught = len(compromised & sc.isolated) / max(1, len(compromised))
    return (
        r["isolated_benign_workstation"] * n_ws
        + r["isolated_benign_server"] * n_srv
        + r["isolated_domain_controller"] * n_dc
        + r["per_tick"] * sc.now
        + r["compromised_isolated_share"] * caught
    )


def score(sc: Scenario, report: dict[str, Any], kind: str) -> dict[str, Any]:
    c = config.load("soc")["rewards"]
    contained = not sc.exfiltrated
    compromised = set(sc.compromised)
    benign_iso = [sc.host(h) for h in sc.isolated if h not in compromised]
    n_ws = sum(1 for h in benign_iso if h.kind == "workstation")
    n_srv = sum(1 for h in benign_iso if h.kind == "server" and not h.critical)
    n_dc = sum(1 for h in benign_iso if h.critical)
    caught = len(compromised & sc.isolated) / max(1, len(compromised))
    if kind == "naive":
        reward = c["naive"]["contained"] * contained
    else:
        r = c["robust"]
        reward = (
            r["contained"] * contained
            + r["isolated_benign_workstation"] * n_ws
            + r["isolated_benign_server"] * n_srv
            + r["isolated_domain_controller"] * n_dc
            + r["per_tick"] * sc.ended_at
            + r["compromised_isolated_share"] * caught
        )
    rep_hosts = set(report.get("compromised_hosts") or [])
    rep_accts = set(report.get("compromised_accounts") or [])
    stolen = set(sc.stolen)
    return {
        "reward": float(reward),
        "contained": contained,
        "exfiltrated": sc.exfiltrated,
        "benign_isolated": {"workstations": n_ws, "servers": n_srv, "domain_controller": n_dc},
        "compromised": sorted(compromised),
        "compromised_isolated_share": caught,
        "isolated": sorted(sc.isolated),
        "report_hosts_f1": _f1(rep_hosts, compromised),
        "report_accounts_f1": _f1(rep_accts, stolen) if (rep_accts or stolen) else 1.0,
        "report_initial_access_ok": report.get("initial_access") == sc.initial_access,
        "ticks": sc.ended_at,
    }
