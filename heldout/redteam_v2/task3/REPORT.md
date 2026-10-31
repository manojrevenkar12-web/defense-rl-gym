# Security report

Weakness: CWE-639, Missing authorisation in order.get.
Affected request: `order.get`.

One request that shows the problem: `{"op": "order.get", "user": "alice", "ref": "1002"}`
One request that must keep working: `{"op": "order.get", "user": "alice", "ref": "1001"}`

Access rule: Each order may be read or changed by its owner (the record's `owner` field) and by administrators (the user names in `support.WORLD["admins"]`); nobody else.

Fix `service.py` so that no request can exploit this weakness while every legitimate
request behaves as before. Do not change `support.py`; it is replaced when your fix is
checked. The checks use more requests than the two above.
