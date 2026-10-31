"""statement.get / statement.annotate (seed 900002) with ownership enforced."""

import support
import json

# Candidate owner fields a statement record might carry.
_OWNER_KEYS = ("user", "owner", "account", "holder", "customer",
               "user_id", "owner_id", "account_id")


def _owns(item, user):
    """True only when a present owner field matches the caller."""
    for key in _OWNER_KEYS:
        if key in item:
            return str(item[key]) == str(user)
    # No owner field to check against: refuse rather than leak.
    return False


def get_statement(user, ref):
    item = support.records("statements").get(ref)
    if item is None:
        return {"status": 404, "body": "not found"}
    if not _owns(item, user):
        return {"status": 403, "body": "forbidden"}
    return {"status": 200, "body": json.dumps(item)}


def annotate_statement(user, ref, note):
    item = support.records("statements").get(ref)
    if item is None:
        return {"status": 404, "body": "not found"}
    if not _owns(item, user):
        return {"status": 403, "body": "forbidden"}
    item["memo"] = note
    support.save_record("statements", ref, item)
    return {"status": 200, "body": "saved"}


def health():
    return {"status": 200, "body": "ok"}


ROUTES = {
    "statement.get": (get_statement, ['user', 'ref']),
    "statement.annotate": (annotate_statement, ['user', 'ref', 'note']),
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
