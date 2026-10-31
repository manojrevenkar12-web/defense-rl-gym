"""lookup.account (seed 900005) with the SQL injection genuinely fixed."""

import support
import json


def lookup_account(handle):
    conn = support.connect()
    rows = conn.execute(
        "SELECT handle, email FROM accounts WHERE handle = ? AND role = 'user'",
        (handle,),
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
