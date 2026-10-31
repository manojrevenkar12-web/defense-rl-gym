# Security report

Weakness: CWE-22, Path traversal in manual.read.
Affected request: `manual.read`.

One request that shows the problem: `{"op": "manual.read", "name": "../secret.txt"}`
One request that must keep working: `{"op": "manual.read", "name": "readme.txt"}`

Fix `service.py` so that no request can exploit this weakness while every legitimate
request behaves as before. Do not change `support.py`; it is replaced when your fix is
checked. The checks use more requests than the two above.
