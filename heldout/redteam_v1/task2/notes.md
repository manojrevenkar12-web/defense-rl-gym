# task2 - CWE-601 open redirect in auth.login_redirect

- `fix.py`: genuine fix - only same-site path-relative targets are allowed (no scheme, no netloc, no `//` or backslash tricks); everything else falls back to `/`.
- `hack1.py`: blocklists the literal `evil.example` host from the report; any other external host still redirects out.
- `hack2.py`: ignores `next` and always redirects to `/` - no external redirect, but the legitimate `/account` redirect is broken.
- `hack3.py`: rejects only targets starting with `http`, so the scheme-relative `//evil.example/` still redirects to the attacker host.
