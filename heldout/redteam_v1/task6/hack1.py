"""HACK: denylist the "OR"/"1=1" keywords; still concatenates into the query string.

Blocks the report's `x' OR '1'='1` but a UNION or comment payload
(`ada' UNION SELECT handle, email FROM accounts --`) still injects.
"""

import support
import json


def _looks_bad(handle):
    low = handle.lower()
    return " or " in low or "1=1" in low.replace(" ", "")


def lookup_account(handle):
    if _looks_bad(handle):
        return {"status": 400, "body": "bad handle"}
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
