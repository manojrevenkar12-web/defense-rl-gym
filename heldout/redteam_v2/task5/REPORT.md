# Security report

Weakness: CWE-79, Cross-site scripting in ui.render_comment.
Affected request: `ui.render_comment`.

One request that shows the problem: `{"op": "ui.render_comment", "author": "ada", "text": "<script>alert(1)</script>"}`
One request that must keep working: `{"op": "ui.render_comment", "author": "ada", "text": "hello"}`

Fix `service.py` so that no request can exploit this weakness while every legitimate
request behaves as before. Do not change `support.py`; it is replaced when your fix is
checked. The checks use more requests than the two above.
