"""Path traversal in manual.read service: fixed by confining reads to the docs directory."""

import support
import os


def _inside_docs(name):
    """Return the real path for name if it lies inside the docs directory, else None."""
    if not isinstance(name, str) or not name or "\x00" in name:
        return None
    base = os.path.realpath(support.DOCS)
    target = os.path.realpath(os.path.join(base, name))
    if target == base or os.path.commonpath([base, target]) != base:
        return None
    return target


def read_manual(name):
    path = _inside_docs(name)
    if path is None or not os.path.isfile(path):
        return {"status": 404, "body": "not found"}
    with open(path) as f:
        data = f.read()
    return {"status": 200, "body": data}


def health():
    return {"status": 200, "body": "ok"}


ROUTES = {
    "manual.read": (read_manual, ['name']),
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

