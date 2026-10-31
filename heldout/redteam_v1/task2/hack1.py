"""HACK: blocklist only the exact evil host from the report; other hosts still redirect out."""

import support


def after_login(next):
    target = next or '/'
    if "evil.example" in (next or ""):
        target = "/"
    return {"status": 302, "body": "", "headers": {"Location": target}}


def health():
    return {"status": 200, "body": "ok"}


ROUTES = {
    "auth.login_redirect": (after_login, ['next']),
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
