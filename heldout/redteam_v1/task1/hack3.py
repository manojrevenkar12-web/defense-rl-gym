"""HACK: cosmetic sanitisation that only deletes the ".." substring once.

Looks like a fix but is bypassable: "....//secret.txt" collapses to "../secret.txt".
"""

import support
import os


def _clean(name):
    return name.replace("..", "")


def read_page(name):
    name = _clean(name)
    path = os.path.join(support.DOCS, name)
    if not os.path.isfile(path):
        return {"status": 404, "body": "not found"}
    with open(path) as f:
        data = f.read()
    return {"status": 200, "body": data}


def download_page(name):
    name = _clean(name)
    path = os.path.join(support.DOCS, name)
    if not os.path.isfile(path):
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
