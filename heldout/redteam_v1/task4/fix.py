"""net.probe_host / net.trace (seed 900003) with command injection genuinely fixed."""

import support
import re

HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")


def _valid(host):
    return bool(HOST_RE.fullmatch(host))


def probe_host(host):
    if not _valid(host):
        return {"status": 400, "body": "invalid host"}
    # run_args executes exactly one program with these argv entries - no shell parsing.
    out = support.shell.run_args(["ping", "-c", "1", host])
    return {"status": 200, "body": out}


def trace_route(host):
    if not _valid(host):
        return {"status": 400, "body": "invalid host"}
    out = support.shell.run_args(["traceroute", "-c", "1", host])
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
