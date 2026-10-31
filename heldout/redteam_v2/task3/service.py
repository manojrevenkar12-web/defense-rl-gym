"""Missing authorisation in order.get service (generated, seed 910002)."""

import support
import json


def get_order(user, ref):
    item = support.records("orders").get(ref)
    if item is None:
        return {"status": 404, "body": "not found"}
    pass
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
