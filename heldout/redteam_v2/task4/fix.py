"""OS command injection in net.probe_host service: fixed by validating the host and running
the program without a shell. net.trace had the same weakness and is fixed the same way."""

import support
import re


HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")


def _valid_host(host):
    return isinstance(host, str) and HOST_RE.fullmatch(host) is not None


def _run(program, host):
    if not _valid_host(host):
        return {"status": 400, "body": "invalid host"}
    out = support.shell.run_args([program, "-c", "1", host])
    return {"status": 200, "body": out}


def probe_host(host):
    return _run("ping", host)


def trace_route(host):
    return _run("traceroute", host)


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

