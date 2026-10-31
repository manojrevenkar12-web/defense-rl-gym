"""ui.render_review (seed 900004) with the XSS genuinely fixed."""

import support

ENTITIES = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;'}


def ESCAPE(s):
    return ''.join(ENTITIES.get(c, c) for c in s)


def render_review(author, text):
    # Both fields land in HTML (author also inside a single-quoted attribute), so escape both.
    a, t = ESCAPE(author), ESCAPE(text)
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
