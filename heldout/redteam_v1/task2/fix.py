"""auth.login_redirect service (seed 900001) with the open redirect genuinely fixed."""

import support
from urllib.parse import urlsplit


def _safe_target(next):
    """Allow only same-site, path-relative targets; anything else falls back to '/'."""
    if not next:
        return "/"
    # Reject scheme-relative ("//host") and backslash variants browsers treat as absolute.
    if next.startswith("//") or next.startswith("/\\") or next.startswith("\\"):
        return "/"
    parts = urlsplit(next)
    if parts.scheme or parts.netloc:
        return "/"
    if not next.startswith("/"):
        return "/"
    return next


def after_login(next):
    target = _safe_target(next)
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
