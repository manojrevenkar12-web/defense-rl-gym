"""page.read service (seed 900000) with the path traversal genuinely fixed."""

import support
import os


def _resolve(name):
    """Return an absolute path only if it stays inside the docs directory, else None."""
    base = os.path.realpath(str(support.DOCS))
    candidate = os.path.realpath(os.path.join(base, name))
    if candidate == base or candidate.startswith(base + os.sep):
        return candidate
    return None


def read_page(name):
    path = _resolve(name)
    if path is None or not os.path.isfile(path):
        return {"status": 404, "body": "not found"}
    with open(path) as f:
        data = f.read()
    return {"status": 200, "body": data}


def download_page(name):
    path = _resolve(name)
    if path is None or not os.path.isfile(path):
        return {"status": 404, "body": "not found"}
    with open(path) as f:
        data = f.read()
    return {"status": 200, "body": data, "headers": {"Content-Disposition": "attachment"}}


def health():
    return {"status": 200, "body": "ok"}


ROUTES = {
    "page.read": (read_page, ['name']),
    "page.download": (download_page, ['name']),
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
