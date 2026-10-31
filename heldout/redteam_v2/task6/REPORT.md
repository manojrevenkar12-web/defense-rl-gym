# Security report

Weakness: CWE-89, SQL injection in lookup.student.
Affected request: `lookup.student`.

One request that shows the problem: `{"op": "lookup.student", "name": "x' OR '1'='1"}`
One request that must keep working: `{"op": "lookup.student", "name": "ada"}`

Fix `service.py` so that no request can exploit this weakness while every legitimate
request behaves as before. Do not change `support.py`; it is replaced when your fix is
checked. The checks use more requests than the two above.
