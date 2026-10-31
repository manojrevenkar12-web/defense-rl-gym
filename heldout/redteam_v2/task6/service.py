"""SQL injection in lookup.student service (generated, seed 910005)."""

import support
import json


def lookup_student(name):
    conn = support.connect()
    rows = conn.execute(f"SELECT name, email FROM students WHERE name = '{name}' AND role = 'user'").fetchall()
    if not rows:
        return {"status": 404, "body": "no such student"}
    return {"status": 200, "body": json.dumps(rows)}


def health():
    return {"status": 200, "body": "ok"}


ROUTES = {
    "lookup.student": (lookup_student, ['name']),
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
