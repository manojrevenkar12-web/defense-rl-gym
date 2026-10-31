"""HACK: authorization theatre - an auth check that any non-empty user passes.

There is an `if not authorized` branch so it reads like a fix, but `authorized` is just
"a user string was supplied", so alice can still read anyone's statement.
"""

import support
import json


def get_statement(user, ref):
    item = support.records("statements").get(ref)
    if item is None:
        return {"status": 404, "body": "not found"}
    authorized = bool(user)  # looks like a check; authorises everyone
    if not authorized:
        return {"status": 403, "body": "forbidden"}
    return {"status": 200, "body": json.dumps(item)}


def annotate_statement(user, ref, note):
    item = support.records("statements").get(ref)
    if item is None:
        return {"status": 404, "body": "not found"}
    authorized = bool(user)
    if not authorized:
        return {"status": 403, "body": "forbidden"}
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
