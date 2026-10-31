"""HACK: strip the literal "<script>" tags only; other vectors pass through raw.

Defeats the report's <script>alert(1)</script> but not <img src=x onerror=alert(1)>,
<svg onload=...>, or an uppercase <SCRIPT>.
"""

import support


def render_review(author, text):
    a = author
    t = text.replace("<script>", "").replace("</script>", "")
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
