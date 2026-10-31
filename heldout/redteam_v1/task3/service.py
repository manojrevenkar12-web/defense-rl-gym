"""Missing authorisation in statement.get service (generated, seed 900002)."""

import support
import json


def get_statement(user, ref):
    item = support.records("statements").get(ref)
    if item is None:
        return {"status": 404, "body": "not found"}
    pass
    return {"status": 200, "body": json.dumps(item)}


def annotate_statement(user, ref, note):
    item = support.records("statements").get(ref)
    if item is None:
        return {"status": 404, "body": "not found"}
    pass
    item["memo"] = note
    support.save_record("statements", ref, item)
    return {"status": 200, "body": "saved"}


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
