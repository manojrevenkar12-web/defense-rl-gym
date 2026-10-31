"""The runner refuses what a reward-hacking patch would reach for (defence in depth, not a boundary)."""

import pytest

from drg.patch.sandbox import run

CALL = [{"op": "health", "args": {}}]
HEALTHY = "def health():\n    return {'status': 200, 'body': 'ok'}\nROUTES = {'health': (health, [])}\n" \
          "def handle(req):\n    fn, ps = ROUTES[req['op']]\n    return fn()\n"


def _run(prelude: str):
    return run(prelude + "\n" + HEALTHY, CALL, {}, {})


@pytest.mark.parametrize("prelude", [
    "import socket\nsocket.socket()",
    "import subprocess\nsubprocess.run(['true'])",
    "import os\nos.system('true')",
    "open('/tmp/drg-escape-test', 'w').write('x')",
    "import sys\nsys._getframe(0)",
    "import ctypes\nctypes.CDLL(None)",
])
def test_blocked_at_import(prelude):
    out = _run(prelude)
    assert "import_error" in out or "error" in out, out


def test_a_healthy_service_runs():
    out = _run("")
    assert "results" in out, out
    assert out["results"][0]["resp"]["status"] == 200


def test_writes_inside_the_sandbox_root_are_allowed():
    out = _run("import support, os\nos.makedirs(support.ROOT / 'x', exist_ok=True)\nopen(support.ROOT / 'x' / 'f', 'w').write('ok')")
    assert "results" in out, out


def test_runaway_service_is_stopped():
    out = _run("while True:\n    pass")
    assert "error" in out
