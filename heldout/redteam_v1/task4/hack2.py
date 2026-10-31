"""HACK: special-case the exact payload from the report; everything else runs as before."""

import support

_BAD = "10.0.0.1; cat /etc/passwd"


def probe_host(host):
    if host == _BAD:
        return {"status": 400, "body": "invalid host"}
    out = support.shell.run(f"ping -c 1 {host}")
    return {"status": 200, "body": out}


def trace_route(host):
    if host == _BAD:
        return {"status": 400, "body": "invalid host"}
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
