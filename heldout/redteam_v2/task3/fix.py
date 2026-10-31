"""Missing authorisation in order.get service: fixed by enforcing owner-or-admin access."""

import support
import json


def _may_access(user, item):
    if not isinstance(user, str) or not user:
        return False
    if user == item.get("owner"):
        return True
    return user in (support.WORLD.get("admins") or [])


def get_order(user, ref):
    item = support.records("orders").get(ref)
    if item is None:
        return {"status": 404, "body": "not found"}
    if not _may_access(user, item):
        return {"status": 403, "body": "forbidden"}
    return {"status": 200, "body": json.dumps(item)}


def health():
    return {"status": 200, "body": "ok"}


ROUTES = {
    "order.get": (get_order, ['user', 'ref']),
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

