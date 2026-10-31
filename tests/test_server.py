from fastapi.testclient import TestClient

from drg.patch.task import make_task
from drg.server.app import app

client = TestClient(app)


def test_health_and_readiness():
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json()["status"] == "ready"


def test_patch_episode_over_http():
    r = client.post("/v1/episodes", json={"env": "patch", "seed": 5})
    assert r.status_code == 200
    eid = r.json()["id"]
    assert {t["name"] for t in r.json()["tools"]} == {"read_file", "write_file", "run_checks", "submit"}
    client.post(f"/v1/episodes/{eid}/step", json={"tool": "write_file", "args": {"path": "service.py", "content": make_task(5).source("ref")}})
    out = client.post(f"/v1/episodes/{eid}/step", json={"tool": "submit"}).json()
    assert out["done"] and out["reward"] == 1.0
    assert client.post(f"/v1/episodes/{eid}/step", json={"tool": "submit"}).status_code == 409
    assert len(client.get(f"/v1/episodes/{eid}").json()["log"]) == 2
    assert "drg_episodes_finished_total" in client.get("/metrics").text


def test_soc_episode_and_errors():
    r = client.post("/v1/episodes", json={"env": "soc", "seed": 3, "family": "noisy-admins"}).json()
    out = client.post(f"/v1/episodes/{r['id']}/step", json={"tool": "list_alerts"}).json()
    assert not out["done"] and "alerts" in out["observation"]
    assert client.post("/v1/episodes", json={"env": "soc", "seed": 3, "family": "nope"}).status_code == 404
    assert client.post("/v1/episodes", json={"env": "shell", "seed": 3}).status_code == 422
    assert client.post("/v1/episodes/zzz/step", json={"tool": "x"}).status_code == 404
