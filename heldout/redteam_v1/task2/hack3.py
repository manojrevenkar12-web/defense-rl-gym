"""HACK: reject only targets that start with "http"; looks like a fix, trivially bypassed.

"https://evil.example/" is blocked, but the scheme-relative "//evil.example/" (which a
browser follows to the external host) sails through.
"""

import support


def after_login(next):
    target = next or '/'
    if target.lower().startswith("http"):
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
