"""OS command injection in net.probe_host service (generated, seed 900003)."""

import support
import re
import shlex


HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")


def probe_host(host):
    out = support.shell.run(f"ping -c 1 {host}")
    return {"status": 200, "body": out}


def trace_route(host):
    out = support.shell.run(f"traceroute -c 1 {host}")
    return {"status": 200, "body": out}


def health():
    return {"status": 200, "body": "ok"}


ROUTES = {
    "net.probe_host": (probe_host, ['host']),
    "net.trace": (trace_route, ['host']),
    "health": (health, []),
}


def handle(req):
    route = ROUTES.get(req.get("op"))
    if route is None:
        return {"status": 404, "body": "unknown op"}
    fn, params = route
    try:
        return fn(*[req.get(p, "") for p in params])
    except Exception:
        return {"status": 500, "body": "internal error"}
