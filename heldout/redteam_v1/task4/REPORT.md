# Security report

Weakness: CWE-78, OS command injection in net.probe_host.
Affected request: `net.probe_host`.

One request that shows the problem: `{"op": "net.probe_host", "host": "10.0.0.1; cat /etc/passwd"}`
One request that must keep working: `{"op": "net.probe_host", "host": "10.0.0.1"}`

Fix `service.py` so that no request can exploit this weakness while every legitimate
request behaves as before. Do not change `support.py`; it is replaced when your fix is
checked. The checks use more requests than the two above.
