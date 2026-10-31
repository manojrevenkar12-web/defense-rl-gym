"""The environments as a service, for a training cluster to call.

POST /v1/episodes {"env": "patch"|"soc", "seed": int, "family"?: str}  -> id, first observation, tools
POST /v1/episodes/{id}/step {"tool": str, "args": {...}}               -> observation, reward, done
GET  /v1/episodes/{id}                                                  -> the step log so far
GET  /healthz  /readyz  /metrics

Episodes are deterministic in their seed. Patch grading runs in sandbox subprocesses with
resource limits; the server process never imports a submitted service.
"""

from __future__ import annotations

import threading
import time
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from ..harness.agent import make_env

app = FastAPI(title="defense-rl-gym", version="0.1.0")
_lock = threading.Lock()
_episodes: dict[str, dict[str, Any]] = {}
_metrics = {"episodes": 0, "steps": 0, "finished": 0, "reward_sum": 0.0}
TTL_S = 1800


class Start(BaseModel):
    env: str = Field(pattern="^(patch|soc)$")
    seed: int = Field(ge=0)
    family: str | None = None


class StepIn(BaseModel):
    tool: str
    args: dict[str, Any] = {}


def _gc() -> None:
    now = time.time()
    for k in [k for k, v in _episodes.items() if now - v["seen"] > TTL_S]:
        del _episodes[k]


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
def readyz() -> dict[str, Any]:
    env, _ = make_env("soc", 0)
    return {"status": "ready", "episodes": len(_episodes), "soc_hosts": len(env.sc.hosts)}


@app.post("/v1/episodes")
def start(body: Start) -> dict[str, Any]:
    try:
        env, tools = make_env(body.env, body.seed, body.family)
    except (KeyError, FileNotFoundError) as e:
        raise HTTPException(404, f"unknown family {body.family}") from e
    first = env.reset()
    eid = uuid.uuid4().hex
    with _lock:
        _gc()
        _episodes[eid] = {"env": env, "kind": body.env, "seen": time.time(), "log": [], "done": False}
        _metrics["episodes"] += 1
    return {"id": eid, "observation": first, "tools": tools}


@app.post("/v1/episodes/{eid}/step")
def step(eid: str, body: StepIn) -> dict[str, Any]:
    ep = _episodes.get(eid)
    if ep is None:
        raise HTTPException(404, "no such episode (expired?)")
    if ep["done"]:
        raise HTTPException(409, "episode is over")
    out, r, done = ep["env"].step(body.tool, body.args)
    ep["seen"] = time.time()
    ep["log"].append({"tool": body.tool, "reward": r, "done": done})
    ep["done"] = done
    with _lock:
        _metrics["steps"] += 1
        if done:
            _metrics["finished"] += 1
            _metrics["reward_sum"] += r
    return {"observation": out, "reward": r, "done": done}


@app.get("/v1/episodes/{eid}")
def get(eid: str) -> dict[str, Any]:
    ep = _episodes.get(eid)
    if ep is None:
        raise HTTPException(404, "no such episode")
    return {"env": ep["kind"], "done": ep["done"], "log": ep["log"]}


@app.get("/metrics")
def metrics() -> PlainTextResponse:
    m = _metrics
    lines = [
        "# TYPE drg_episodes_total counter", f"drg_episodes_total {m['episodes']}",
        "# TYPE drg_steps_total counter", f"drg_steps_total {m['steps']}",
        "# TYPE drg_episodes_finished_total counter", f"drg_episodes_finished_total {m['finished']}",
        "# TYPE drg_reward_sum counter", f"drg_reward_sum {m['reward_sum']:.4f}",
        "# TYPE drg_open_episodes gauge", f"drg_open_episodes {len(_episodes)}",
    ]
    return PlainTextResponse("\n".join(lines) + "\n")
