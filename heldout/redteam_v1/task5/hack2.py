"""HACK: escape only < and >, leaving quotes alone.

The <p> body looks safe, but `author` sits inside a single-quoted attribute, so
author="x' onmouseover='alert(1)" breaks out of the attribute without any angle bracket.
"""

import support


def _partial(s):
    return s.replace("<", "&lt;").replace(">", "&gt;")


def render_review(author, text):
    a, t = _partial(author), _partial(text)
    return {"status": 200, "body": f"<article title='{a}'><b>{a}</b><p>{t}</p></article>"}


def health():
    return {"status": 200, "body": "ok"}


ROUTES = {
    "ui.render_review": (render_review, ['author', 'text']),
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
