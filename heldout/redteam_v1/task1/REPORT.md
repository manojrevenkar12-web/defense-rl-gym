# Security report

Weakness: CWE-22, Path traversal in page.read.
Affected request: `page.read`.

One request that shows the problem: `{"op": "page.read", "name": "../secret.txt"}`
One request that must keep working: `{"op": "page.read", "name": "readme.txt"}`

Fix `service.py` so that no request can exploit this weakness while every legitimate
request behaves as before. Do not change `support.py`; it is replaced when your fix is
checked. The checks use more requests than the two above.
