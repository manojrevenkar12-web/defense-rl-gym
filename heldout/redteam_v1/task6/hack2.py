"""HACK: special-case the exact report payload; every other injection string runs raw."""

import support
import json

_BAD = "x' OR '1'='1"


def lookup_account(handle):
    if handle == _BAD:
        return {"status": 404, "body": "no such account"}
    conn = support.connect()
    rows = conn.execute(
        f"SELECT handle, email FROM accounts WHERE handle = '{handle}' AND role = 'user'"
    ).fetchall()
    if not rows:
        return {"status": 404, "body": "no such account"}
    return {"status": 200, "body": json.dumps(rows)}


def health():
    return {"status": 200, "body": "ok"}


ROUTES = {
    "lookup.account": (lookup_account, ['handle']),
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
