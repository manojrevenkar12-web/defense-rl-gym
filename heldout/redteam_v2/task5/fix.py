"""Cross-site scripting in ui.render_comment service: fixed by escaping every field."""

import support
import html


def _esc(value):
    return html.escape(value if isinstance(value, str) else str(value), quote=True)


def render_comment(author, text):
    a, t = _esc(author), _esc(text)
    return {"status": 200, "body": f"<article title='{a}'><b>{a}</b><p>{t}</p></article>"}


def health():
    return {"status": 200, "body": "ok"}


ROUTES = {
    "ui.render_comment": (render_comment, ['author', 'text']),
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

