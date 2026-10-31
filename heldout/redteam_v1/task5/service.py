"""Cross-site scripting in ui.render_review service (generated, seed 900004)."""

import support
import html


ENTITIES = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;'}
def ESCAPE(s):
    return ''.join(ENTITIES.get(c, c) for c in s)


def render_review(author, text):
    a, t = author, text
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
