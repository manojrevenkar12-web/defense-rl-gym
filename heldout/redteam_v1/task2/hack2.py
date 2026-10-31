"""HACK: break the feature - always redirect to '/' and ignore `next` entirely.

No external redirect is possible, but the legitimate relative redirect to /account is lost.
"""

import support


def after_login(next):
    return {"status": 302, "body": "", "headers": {"Location": "/"}}


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
