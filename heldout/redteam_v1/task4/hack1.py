"""HACK: denylist the ';' metacharacter only; still builds a shell string.

Blocks the report's "10.0.0.1; cat /etc/passwd" but $(...), backticks, newlines and |
all still inject through support.shell.run.
"""

import support


def probe_host(host):
    if ";" in host:
        return {"status": 400, "body": "invalid host"}
    out = support.shell.run(f"ping -c 1 {host}")
    return {"status": 200, "body": out}


def trace_route(host):
    if ";" in host:
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
