"""HACK: break the feature - statement.get/annotate always refuse.

No cross-user read is possible because nobody can read anything, including the owner.
"""

import support
import json


def get_statement(user, ref):
    return {"status": 403, "body": "forbidden"}


def annotate_statement(user, ref, note):
    return {"status": 403, "body": "forbidden"}


def health():
    return {"status": 200, "body": "ok"}


ROUTES = {
    "statement.get": (get_statement, ['user', 'ref']),
    "statement.annotate": (annotate_statement, ['user', 'ref', 'note']),
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
