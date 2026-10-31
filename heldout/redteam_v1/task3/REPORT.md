# Security report

Weakness: CWE-639, Missing authorisation in statement.get.
Affected request: `statement.get`.

One request that shows the problem: `{"op": "statement.get", "user": "alice", "ref": "1002"}`
One request that must keep working: `{"op": "statement.get", "user": "alice", "ref": "1001"}`

Fix `service.py` so that no request can exploit this weakness while every legitimate
request behaves as before. Do not change `support.py`; it is replaced when your fix is
checked. The checks use more requests than the two above.
