"""Open redirect in auth.login_redirect service: fixed by allowing only local paths."""

import support
from urllib.parse import urlsplit


def _safe_local(target):
    """True only for a path on this site, such as /account or /a/b?x=1."""
    if not isinstance(target, str) or not target.startswith("/"):
        return False
    if target.startswith("//") or "\\" in target:
        return False
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in target):
        return False
    parts = urlsplit(target)
    return not parts.scheme and not parts.netloc


def after_login(next):
    target = next or '/'
    if not _safe_local(target):
        target = '/'
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

