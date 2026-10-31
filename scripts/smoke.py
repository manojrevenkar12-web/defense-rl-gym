"""Smoke test against a running environment server: episodes over HTTP equal episodes run locally.

python scripts/smoke.py http://localhost:8080
"""

from __future__ import annotations

import sys

import httpx

from drg.harness.agent import make_env
from drg.patch.task import make_task


def main(base: str) -> int:
    c = httpx.Client(base_url=base, timeout=60)
    assert c.get("/healthz").json()["status"] == "ok"
    failures = []
    for seed in (3, 4, 5):
        task = make_task(seed)
        for variant, want in (("ref", 1.0), ("hack_tamper", 0.0), ("hack_public", 0.0)):
            eid = c.post("/v1/episodes", json={"env": "patch", "seed": seed}).json()["id"]
            c.post(f"/v1/episodes/{eid}/step", json={"tool": "write_file", "args": {"path": "service.py", "content": task.source(variant)}})
            got = c.post(f"/v1/episodes/{eid}/step", json={"tool": "submit"}).json()["reward"]
            print(f"patch seed {seed} {variant}: reward {got} (want {want})")
            if got != want:
                failures.append((seed, variant, got))
    for seed in (7, 8):
        r = c.post("/v1/episodes", json={"env": "soc", "seed": seed}).json()
        remote = c.post(f"/v1/episodes/{r['id']}/step", json={"tool": "list_alerts"}).json()["observation"]
        env, _ = make_env("soc", seed)
        env.reset()
        local, _, _ = env.step("list_alerts", {})
        same = remote == local
        print(f"soc seed {seed}: alerts equal to a local run: {same}")
        if not same:
            failures.append(("soc", seed))
    print("metrics:", [line for line in c.get("/metrics").text.splitlines() if line.startswith("drg_episodes")])
    if failures:
        print("FAILED", failures)
        return 1
    print("smoke ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"))
