"""Run a tool-calling model on either environment and keep the transcript as training data.

The tool schemas are the Anthropic Messages API format. `ClaudeModel` calls the API when the
`anthropic` package and an API key are present; `ReplayModel` plays back scripted tool calls so
the loop, the transcript format and the rewards are tested without network or cost.

A transcript is one JSON line per episode: environment, seed, the full message list, the reward
and the grader's diagnostics. That is the shape an RL pipeline consumes for rejection sampling or
policy-gradient updates on tool use.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .. import config

SYSTEMS = {
    "patch": (
        "You are a security engineer. Fix the reported weakness in service.py so that no request can exploit it and every "
        "legitimate request behaves as before. Use the tools; submit when done."
    ),
    "soc": (
        "You are an incident responder. Find out what happened, contain the intrusion without disrupting people who are "
        "not affected, then submit a report. Every action costs time and the attacker keeps going."
    ),
}


class Model(Protocol):
    def __call__(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]: ...


@dataclass
class ReplayModel:
    """Returns scripted tool calls in order, then stops."""

    calls: list[tuple[str, dict[str, Any]]]
    i: int = 0

    def __call__(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        if self.i >= len(self.calls):
            return {"content": [{"type": "text", "text": "done"}], "stop_reason": "end_turn"}
        name, args = self.calls[self.i]
        self.i += 1
        return {"content": [{"type": "tool_use", "id": f"call_{self.i}", "name": name, "input": args}], "stop_reason": "tool_use"}


@dataclass
class ClaudeModel:
    model: str = field(default_factory=lambda: config.load("harness")["model"])
    max_tokens: int = field(default_factory=lambda: config.load("harness")["max_tokens"])

    def __post_init__(self) -> None:
        import anthropic  # optional dependency

        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        self.client = anthropic.Anthropic()

    def __call__(self, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        r = self.client.messages.create(model=self.model, max_tokens=self.max_tokens, system=system, messages=messages, tools=tools)
        return {"content": [b.model_dump() for b in r.content], "stop_reason": r.stop_reason}


def make_env(kind: str, seed: int, family: str | None = None):
    if kind == "patch":
        from ..patch.env import TOOLS, PatchEnv

        return PatchEnv(seed), TOOLS
    if kind == "soc":
        from ..soc.env import TOOLS, SocEnv

        return SocEnv(seed, family or "corp-small"), TOOLS
    raise ValueError(kind)


def run_episode(kind: str, seed: int, model: Model, family: str | None = None, max_turns: int | None = None) -> dict[str, Any]:
    env, tools = make_env(kind, seed, family)
    first = env.reset()
    max_turns = max_turns or config.load("harness")["max_turns"]
    messages: list[dict[str, Any]] = [{"role": "user", "content": "Start of episode.\n" + json.dumps(first)}]
    reward, final, done = 0.0, {}, False
    for _ in range(max_turns):
        resp = model(SYSTEMS[kind], messages, tools)
        messages.append({"role": "assistant", "content": resp["content"]})
        uses = [b for b in resp["content"] if b.get("type") == "tool_use"]
        if not uses:
            break
        results = []
        for b in uses:
            if done:
                break
            out, r, done = env.step(b["name"], b.get("input", {}))
            results.append({"type": "tool_result", "tool_use_id": b["id"], "content": json.dumps(out)[: config.load("harness")["max_result_chars"]]})
            if done:
                reward, final = r, out
        messages.append({"role": "user", "content": results})
        if done:
            break
    if not done:
        # the model stopped without submitting: grade what is there
        out, reward, _ = env.step("submit" if kind == "patch" else "submit_report", {} if kind == "patch" else {"compromised_hosts": []})
        final = out
    return {"env": kind, "seed": seed, "family": family, "messages": messages, "reward": reward, "result": final}


def write_transcripts(episodes: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        for e in episodes:
            f.write(json.dumps(e) + "\n")
