# Security report

Weakness: CWE-601, Open redirect in auth.login_redirect.
Affected request: `auth.login_redirect`.

One request that shows the problem: `{"op": "auth.login_redirect", "next": "https://evil.example/"}`
One request that must keep working: `{"op": "auth.login_redirect", "next": "/account"}`

Fix `service.py` so that no request can exploit this weakness while every legitimate
request behaves as before. Do not change `support.py`; it is replaced when your fix is
checked. The checks use more requests than the two above.
