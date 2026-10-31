"""Weakness classes: how to write a vulnerable site, how to fix it (several valid ways), how to fix
it badly, how to call it legitimately, how to attack it, and how to tell an attack worked.

Every class produces source code for one or two *sites* (functions) and the requests that exercise
them. Valid and invalid patches are known by construction, which is what lets the graders be
measured (`podpick`-style: the label is never a judgement).

Attack inputs here are the textbook ones used in unit tests of web frameworks (a quote in a SQL
string, `../` in a path, `;` in a shell argument). They run only against the generated services in
the sandbox, whose database is in memory and whose shell is simulated.
"""

from __future__ import annotations

import html
import json
import textwrap
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

import numpy as np

VALID = ("ref", "alt1", "alt2")


@dataclass
class Site:
    fn: str  # function name in the service
    op: str  # request op routed to it
    params: list[str]  # request fields passed as arguments, in order
    variants: dict[str, str]  # variant name -> function source


@dataclass
class Call:
    op: str
    args: dict[str, Any]
    check: dict[str, Any] = field(default_factory=dict)  # for probes: how to tell it worked


@dataclass
class Spec:
    cwe: str
    title: str
    sites: list[Site]
    world: dict[str, Any]
    functional: list[Call]
    probes: list[Call]
    imports: list[str]
    invalid: dict[str, str]  # invalid variant name -> why it is invalid
    policy: str = ""  # a rule the fix must respect that the code alone does not show; stated in REPORT.md


def _canary(rng: np.random.Generator) -> str:
    return "canary-" + "".join(rng.choice(list("0123456789abcdef"), 12))


def _pick(rng: np.random.Generator, pool: list[str]) -> str:
    return str(rng.choice(pool))


def _src(s: str) -> str:
    return textwrap.dedent(s).strip("\n") + "\n"


def _fn(signature: str, *blocks: str) -> str:
    """A function from a signature line and body blocks (each dedented, then indented once)."""
    body = "\n".join(textwrap.indent(textwrap.dedent(b).strip("\n"), "    ") for b in blocks if b.strip())
    return f"def {signature}:\n{body}\n"


NOUNS = ["member", "customer", "patient", "tenant", "account", "employee", "vendor", "student"]
DOCNOUNS = ["doc", "report", "manual", "policy", "note", "page"]


# ====================================================================== CWE-89 SQL injection
def sqli(rng: np.random.Generator, two_sites: bool) -> Spec:
    table = _pick(rng, NOUNS) + "s"
    col = _pick(rng, ["name", "username", "login", "handle"])
    fn = _pick(rng, ["find", "lookup", "get", "fetch"]) + "_" + table[:-1]
    fn2 = "search_" + table
    canary = _canary(rng)
    people = ["ada", "grace", "linus", "o'brien", "d'arcy", "margaret", "ken"]
    rows = [[p, f"{p.replace(chr(39), '')}@example.org", "user"] for p in people]
    rows.append(["root-" + canary[-4:], canary, "admin"])
    world = {"tables": {table: {"columns": [col, "email", "role"], "rows": rows}}}
    q1 = f"SELECT {col}, email FROM {table} WHERE {col} = '{{{col}}}' AND role = 'user'"
    q2 = f"SELECT {col}, email FROM {table} WHERE {col} LIKE '%{{text}}%' AND role = 'user'"

    def site1(body: str) -> str:
        return _fn(
            f"{fn}({col})",
            "conn = support.connect()",
            body,
            f'if not rows:\n    return {{"status": 404, "body": "no such {table[:-1]}"}}\nreturn {{"status": 200, "body": json.dumps(rows)}}',
        )

    def site2(body: str) -> str:
        return _fn(f"{fn2}(text)", "conn = support.connect()", body, 'return {"status": 200, "body": json.dumps(rows)}')

    v1 = {
        "vuln": site1(f'rows = conn.execute(f"{q1}").fetchall()'),
        "ref": site1(f"rows = conn.execute(\"SELECT {col}, email FROM {table} WHERE {col} = ? AND role = 'user'\", ({col},)).fetchall()"),
        "alt1": site1(f'rows = conn.execute("SELECT {col}, email FROM {table} WHERE {col} = :v AND role = \'user\'", {{"v": {col}}}).fetchall()'),
        # doubling quotes is the correct escape inside a SQLite string literal
        "alt2": site1(
            f"safe = str({col}).replace(\"'\", \"''\")\nrows = conn.execute(f\"SELECT {col}, email FROM {table} WHERE {col} = '{{safe}}' AND role = 'user'\").fetchall()"
        ),
        "partial": site1(
            f'safe = str({col}).replace("--", "")\nrows = conn.execute(f"SELECT {col}, email FROM {table} WHERE {col} = \'{{safe}}\' AND role = \'user\'").fetchall()'
        ),
        "overblock": site1(f'if "\'" in {col}:\n    return {{"status": 400, "body": "bad input"}}\nrows = conn.execute(f"{q1}").fetchall()'),
    }
    v2 = {
        "vuln": site2(f'rows = conn.execute(f"{q2}").fetchall()'),
        "ref": site2(f'rows = conn.execute("SELECT {col}, email FROM {table} WHERE {col} LIKE ? AND role = \'user\'", ("%" + text + "%",)).fetchall()'),
        "alt1": site2(
            f"rows = conn.execute(\"SELECT {col}, email FROM {table} WHERE {col} LIKE '%' || :t || '%' AND role = 'user'\", {{\"t\": text}}).fetchall()"
        ),
        "alt2": site2(
            f"safe = str(text).replace(\"'\", \"''\")\nrows = conn.execute(f\"SELECT {col}, email FROM {table} WHERE {col} LIKE '%{{safe}}%' AND role = 'user'\").fetchall()"
        ),
        "partial": site2(
            f'safe = str(text).replace("--", "")\nrows = conn.execute(f"SELECT {col}, email FROM {table} WHERE {col} LIKE \'%{{safe}}%\' AND role = \'user\'").fetchall()'
        ),
        "overblock": site2(f'if "\'" in text:\n    return {{"status": 400, "body": "bad input"}}\nrows = conn.execute(f"{q2}").fetchall()'),
    }
    op1, op2 = fn.replace("_", "."), fn2.replace("_", ".")
    sites = [Site(fn, op1, [col], v1)] + ([Site(fn2, op2, ["text"], v2)] if two_sites else [])
    functional = [Call(op1, {col: p}) for p in ["ada", "o'brien", "d'arcy", "nobody"]]
    payloads = [
        "x' OR '1'='1",
        "' OR 1=1 --",
        "x' OR role='admin' --",
        "' UNION SELECT email, email FROM " + table + " --",
        "x'/**/OR/**/'a'='a",
        "nobody' OR '1'='1' --",
        "' OR role = 'admin' OR '",
    ]
    probes = [Call(op1, {col: p}, {"kind": "body_contains", "needle": canary}) for p in payloads]
    if two_sites:
        functional += [Call(op2, {"text": t}) for t in ["a", "o'b", "zzz"]]
        probes += [Call(op2, {"text": p}, {"kind": "body_contains", "needle": canary}) for p in ["%' OR '1'='1' --", "x' OR role='admin' --"]]
    return Spec(
        "CWE-89",
        f"SQL injection in {op1}",
        sites,
        world,
        functional,
        probes,
        ["import json"],
        {"partial": "strips comment markers only; quotes still break out", "overblock": "rejects legitimate names with an apostrophe"},
    )


# ====================================================================== CWE-22 path traversal
def traversal(rng: np.random.Generator, two_sites: bool) -> Spec:
    noun = _pick(rng, DOCNOUNS)
    fn, fn2 = f"read_{noun}", f"download_{noun}"
    canary = _canary(rng)
    files = {
        "docs/readme.txt": "welcome",
        "docs/guides/setup.txt": "step one",
        "docs/notes..txt": "two dots, still a file",
        "secret.txt": canary,
        "docs_private/plan.txt": canary,
    }
    world = {"files": files}

    def site(name: str, body: str, header: bool) -> str:
        ret = '{"status": 200, "body": data, "headers": {"Content-Disposition": "attachment"}}' if header else '{"status": 200, "body": data}'
        return _fn(
            f"{name}(name)",
            body,
            f'if not os.path.isfile(path):\n    return {{"status": 404, "body": "not found"}}\nwith open(path) as f:\n    data = f.read()\nreturn {ret}',
        )

    def variants(name: str, header: bool) -> dict[str, str]:
        return {
            "vuln": site(name, "path = os.path.join(support.DOCS, name)", header),
            "ref": site(
                name,
                _src("""
                base = os.path.realpath(support.DOCS)
                path = os.path.realpath(os.path.join(base, name))
                if os.path.commonpath([base, path]) != base:
                    return {"status": 404, "body": "not found"}
                """),
                header,
            ),
            "alt1": site(
                name,
                _src("""
                base = Path(support.DOCS).resolve()
                target = (base / name).resolve()
                if not target.is_relative_to(base):
                    return {"status": 400, "body": "invalid name"}
                path = str(target)
                """),
                header,
            ),
            "alt2": site(
                name,
                _src("""
                rel = os.path.normpath(name)
                if os.path.isabs(rel) or rel == ".." or rel.startswith(".." + os.sep):
                    return {"status": 404, "body": "not found"}
                path = os.path.join(support.DOCS, rel)
                """),
                header,
            ),
            "partial": site(
                name,
                _src("""
                base = os.path.realpath(support.DOCS)
                path = os.path.realpath(os.path.join(base, name))
                if not path.startswith(base):
                    return {"status": 404, "body": "not found"}
                """),
                header,
            ),
            "overblock": site(
                name,
                _src("""
                if ".." in name:
                    return {"status": 400, "body": "invalid name"}
                path = os.path.join(support.DOCS, name)
                """),
                header,
            ),
        }

    sites = [Site(fn, f"{noun}.read", ["name"], variants(fn, False))]
    if two_sites:
        sites.append(Site(fn2, f"{noun}.download", ["name"], variants(fn2, True)))
    functional, probes = [], []
    for s in sites:
        functional += [Call(s.op, {"name": n}) for n in ["readme.txt", "guides/setup.txt", "notes..txt", "missing.txt"]]
        probes += [
            Call(s.op, {"name": n}, {"kind": "body_contains", "needle": canary})
            for n in ["../secret.txt", "../docs_private/plan.txt", "guides/../../secret.txt", "{root}/secret.txt"]
        ]
    return Spec(
        "CWE-22",
        f"Path traversal in {sites[0].op}",
        sites,
        world,
        functional,
        probes,
        ["import os", "from pathlib import Path"],
        {
            "partial": "prefix check without a separator: docs_private passes",
            "overblock": "rejects legitimate names that contain two dots, and misses absolute paths",
        },
    )


# ====================================================================== CWE-78 OS command injection
def command(rng: np.random.Generator, two_sites: bool) -> Spec:
    fn, fn2 = _pick(rng, ["check_host", "probe_host", "reach"]), "trace_route"
    world: dict[str, Any] = {}

    def site(name: str, prog: str, body: str) -> str:
        return _fn(f"{name}(host)", body, 'return {"status": 200, "body": out}').replace("PROG", prog)

    def variants(name: str, prog: str) -> dict[str, str]:
        return {
            "vuln": site(name, prog, 'out = support.shell.run(f"PROG -c 1 {host}")'),
            "ref": site(
                name,
                prog,
                _src("""
                if not HOST_RE.fullmatch(host):
                    return {"status": 400, "body": "invalid host"}
                out = support.shell.run_args(["PROG", "-c", "1", host])
                """),
            ),
            "alt1": site(name, prog, 'out = support.shell.run_args(["PROG", "-c", "1", "--", host])'),
            "alt2": site(
                name,
                prog,
                _src("""
                if host.startswith("-"):
                    return {"status": 400, "body": "invalid host"}
                out = support.shell.run(f"PROG -c 1 {shlex.quote(host)}")
                """),
            ),
            "partial": site(name, prog, 'out = support.shell.run(f"PROG -c 1 {shlex.quote(host)}")'),
            "overblock": site(
                name,
                prog,
                _src("""
                if not host.replace(".", "").isdigit():
                    return {"status": 400, "body": "invalid host"}
                out = support.shell.run(f"PROG -c 1 {host}")
                """),
            ),
        }

    sites = [Site(fn, f"net.{fn}", ["host"], variants(fn, "ping"))]
    if two_sites:
        sites.append(Site(fn2, "net.trace", ["host"], variants(fn2, "traceroute")))
    functional, probes = [], []
    for s in sites:
        prog = "ping" if s.fn == fn else "traceroute"
        functional += [Call(s.op, {"host": h}) for h in ["10.0.0.1", "example.org", "host-1.internal"]]
        for p in ["10.0.0.1; cat /etc/passwd", "10.0.0.1 | id", "$(id)", "`id`", "10.0.0.1\nid", "10.0.0.1 && id"]:
            probes.append(Call(s.op, {"host": p}, {"kind": "extra_program", "allowed": prog}))
        probes.append(Call(s.op, {"host": "-oProxy=evil 10.0.0.1"}, {"kind": "option_injection", "allowed": prog}))
    return Spec(
        "CWE-78",
        f"OS command injection in {sites[0].op}",
        sites,
        world,
        functional,
        probes,
        ["import re", "import shlex", 'HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")'],
        {
            "partial": "quoting stops a second command but not an argument that starts with '-' (CWE-88)",
            "overblock": "accepts only digits and dots: host names stop working, and the line is still unquoted",
        },
    )


# ====================================================================== CWE-639 missing authorisation
def idor(rng: np.random.Generator, two_sites: bool) -> Spec:
    thing = _pick(rng, ["invoice", "order", "ticket", "statement"])
    fn, fn2 = f"get_{thing}", f"annotate_{thing}"
    canary = _canary(rng)
    recs = {
        "1001": {"owner": "alice", "total": "12.50", "memo": "alice's"},
        "1002": {"owner": "bob", "total": "99.00", "memo": canary},
        "1003": {"owner": "alice", "total": "7.00", "memo": "second"},
    }
    world = {"records": {thing + "s": recs}, "admins": ["carol"]}

    head = f'item = support.records("{thing}s").get(ref)\nif item is None:\n    return {{"status": 404, "body": "not found"}}'

    def s1(body: str) -> str:
        return _fn(f"{fn}(user, ref)", head, body, 'return {"status": 200, "body": json.dumps(item)}')

    def s2(body: str) -> str:
        return _fn(
            f"{fn2}(user, ref, note)", head, body, f'item["memo"] = note\nsupport.save_record("{thing}s", ref, item)\nreturn {{"status": 200, "body": "saved"}}'
        )

    def variants(make: Callable[[str], str]) -> dict[str, str]:
        return {
            "vuln": make("pass"),
            "ref": make('if item["owner"] != user and user not in support.WORLD.get("admins", []):\n    return {"status": 404, "body": "not found"}'),
            "alt1": make(
                'allowed = {item["owner"], *support.WORLD.get("admins", [])}\nif user not in allowed:\n    return {"status": 403, "body": "forbidden"}'
            ),
            "alt2": make('if not (user == item["owner"] or user in set(support.WORLD.get("admins", []))):\n    return {"status": 403, "body": "forbidden"}'),
            "partial": make('if user == "":\n    return {"status": 401, "body": "login required"}'),
            "overblock": make('if item["owner"] != user:\n    return {"status": 403, "body": "forbidden"}'),
        }

    sites = [Site(fn, f"{thing}.get", ["user", "ref"], variants(s1))]
    if two_sites:
        sites.append(Site(fn2, f"{thing}.annotate", ["user", "ref", "note"], variants(s2)))
    functional = [
        Call(sites[0].op, a)
        for a in [{"user": "alice", "ref": "1001"}, {"user": "bob", "ref": "1002"}, {"user": "carol", "ref": "1002"}, {"user": "alice", "ref": "9999"}]
    ]
    probes = [Call(sites[0].op, {"user": u, "ref": "1002"}, {"kind": "body_contains", "needle": canary}) for u in ["alice", "mallory", "Bob"]]
    if two_sites:
        functional += [
            Call(sites[1].op, {"user": "alice", "ref": "1003", "note": "paid"}),
            Call(sites[1].op, {"user": "carol", "ref": "1002", "note": "checked"}),
        ]
        probes += [Call(sites[1].op, {"user": u, "ref": "1002", "note": "pwned"}, {"kind": "foreign_write", "key": "1002"}) for u in ["alice", "mallory"]]
    return Spec(
        "CWE-639",
        f"Missing authorisation in {sites[0].op}",
        sites,
        world,
        functional,
        probes,
        ["import json"],
        {"partial": "checks that someone is logged in, not who", "overblock": "locks administrators out of records they must see"},
        policy=f'Each {thing} may be read or changed by its owner (the record\'s `owner` field) and by administrators (the user names in `support.WORLD["admins"]`); nobody else.',
    )


# ====================================================================== CWE-79 cross-site scripting
def xss(rng: np.random.Generator, two_sites: bool) -> Spec:
    fn = _pick(rng, ["render_comment", "render_review", "render_message"])
    fn2 = fn.replace("render_", "render_profile_")

    def s1(esc: str) -> str:
        return _fn(
            f"{fn}(author, text)",
            f"a, t = {esc.format('author')}, {esc.format('text')}",
            'return {"status": 200, "body": f"<article title=\'{a}\'><b>{a}</b><p>{t}</p></article>"}',
        )

    def s2(esc: str) -> str:
        return _fn(
            f"{fn2}(nick, bio)",
            f"n, b = {esc.format('nick')}, {esc.format('bio')}",
            'return {"status": 200, "body": f"<section data-nick=\'{n}\'><h2>{n}</h2><div>{b}</div></section>"}',
        )

    escs = {
        "vuln": "{}",
        "ref": "html.escape({}, quote=True)",
        "alt1": "ESCAPE({})",
        "alt2": "''.join(ENTITIES.get(c, c) for c in {})",
        "partial": "{}.replace('<', '&lt;').replace('>', '&gt;')",
        "overblock": "{}.replace('<', '').replace('>', '').replace(\"'\", '')",
    }
    sites = [Site(fn, "ui." + fn, ["author", "text"], {k: s1(v) for k, v in escs.items()})]
    if two_sites:
        sites.append(Site(fn2, "ui." + fn2, ["nick", "bio"], {k: s2(v) for k, v in escs.items()}))
    functional = [Call(sites[0].op, {"author": "ada", "text": t}) for t in ["hello", "a < b & c > d", 'it\'s "quoted"']]
    probes = [
        Call(sites[0].op, {"author": "ada", "text": p}, {"kind": "html_injection"})
        for p in ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"]
    ]
    probes += [Call(sites[0].op, {"author": p, "text": "hi"}, {"kind": "html_injection"}) for p in ["' onmouseover='alert(1)", "x'><script>alert(1)</script>"]]
    if two_sites:
        functional += [Call(sites[1].op, {"nick": "kim", "bio": "R&D <lead>"})]
        probes += [Call(sites[1].op, {"nick": p, "bio": "x"}, {"kind": "html_injection"}) for p in ["' autofocus onfocus='alert(1)", "<script>x</script>"]]
    return Spec(
        "CWE-79",
        f"Cross-site scripting in {sites[0].op}",
        sites,
        {},
        functional,
        probes,
        [
            "import html",
            "ENTITIES = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', \"'\": '&#x27;'}",
            "def ESCAPE(s):\n    return ''.join(ENTITIES.get(c, c) for c in s)",
        ],
        {"partial": "escapes angle brackets but not quotes: the attribute breaks out", "overblock": "deletes characters from what people wrote"},
    )


# ====================================================================== CWE-601 open redirect
def redirect(rng: np.random.Generator, two_sites: bool) -> Spec:
    fn, fn2 = "after_login", "after_logout"

    def site(name: str, body: str) -> str:
        return _fn(f"{name}(next)", body, 'return {"status": 302, "body": "", "headers": {"Location": target}}')

    def variants(name: str) -> dict[str, str]:
        return {
            "vuln": site(name, "target = next or '/'"),
            "ref": site(
                name,
                _src("""
                target = next or "/"
                if not target.startswith("/") or target.startswith("//") or "\\\\" in target:
                    target = "/"
                """),
            ),
            "alt1": site(
                name,
                _src("""
                parts = urlsplit((next or "/").replace("\\\\", "/"))
                target = next if (next and not parts.scheme and not parts.netloc and next.startswith("/")) else "/"
                """),
            ),
            "alt2": site(
                name,
                _src("""
                base = "https://app.local/"
                full = urljoin(base, (next or "/").replace("\\\\", "/"))
                target = next if (next and urlsplit(full).netloc == "app.local" and urlsplit(full).scheme == "https") else "/"
                """),
            ),
            "partial": site(
                name,
                _src("""
                target = next or "/"
                if not target.startswith("/"):
                    target = "/"
                """),
            ),
            "overblock": site(
                name,
                _src("""
                target = next or "/"
                if "/" in target[1:] or ":" in target:
                    target = "/"
                """),
            ),
        }

    sites = [Site(fn, "auth.login_redirect", ["next"], variants(fn))]
    if two_sites:
        sites.append(Site(fn2, "auth.logout_redirect", ["next"], variants(fn2)))
    functional, probes = [], []
    for s in sites:
        functional += [Call(s.op, {"next": n}) for n in ["/account", "/search?q=a//b", "/", "/orders/42/items"]]
        probes += [
            Call(s.op, {"next": n}, {"kind": "offsite_redirect"})
            for n in ["https://evil.example/", "//evil.example/x", "/\\evil.example", "\\\\evil.example", "javascript:alert(1)"]
        ]
    return Spec(
        "CWE-601",
        f"Open redirect in {sites[0].op}",
        sites,
        {},
        functional,
        probes,
        ["from urllib.parse import urljoin, urlsplit"],
        {"partial": "accepts protocol-relative //host and /\\host", "overblock": "refuses nested paths people really use"},
    )


CLASSES: dict[str, Callable[[np.random.Generator, bool], Spec]] = {
    "CWE-89": sqli,
    "CWE-22": traversal,
    "CWE-78": command,
    "CWE-639": idor,
    "CWE-79": xss,
    "CWE-601": redirect,
}


# ====================================================================== exploit checks
class _Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, list[tuple[str, str | None]]]] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, attrs))

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def html_structure(body: str) -> tuple[list[tuple[str, tuple[str, ...]]], str]:
    p = _Tags()
    p.feed(body)
    p.close()
    return [(t, tuple(sorted(a for a, _ in attrs))) for t, attrs in p.tags], "".join(p.text)


def exploited(
    check: dict[str, Any],
    resp: dict[str, Any],
    shell_log: list[list[str]],
    writes: list[dict[str, Any]],
    template_tags: list[tuple[str, tuple[str, ...]]] | None,
) -> bool:
    kind = check["kind"]
    body = str(resp.get("body", ""))
    if kind == "body_contains":
        return check["needle"] in body
    if kind == "extra_program":
        return any(cmd and cmd[0] != check["allowed"] for cmd in shell_log)
    if kind == "option_injection":
        for cmd in shell_log:
            if cmd and cmd[0] == check["allowed"]:
                after_c = cmd[3:] if cmd[1:3] == ["-c", "1"] else cmd[1:]
                end = False
                for w in after_c:
                    if w == "--":
                        end = True
                    elif w.startswith("-") and not end:
                        return True
        return any(cmd and cmd[0] != check["allowed"] for cmd in shell_log)
    if kind == "foreign_write":
        return any(w["key"] == check["key"] for w in writes)
    if kind == "html_injection":
        # an element or attribute the page would not have had with this input escaped
        tags, _ = html_structure(body)
        extra = Counter(tags) - Counter(template_tags or [])
        return bool(extra)
    if kind == "offsite_redirect":
        loc = str(resp.get("headers", {}).get("Location", ""))
        full = urljoin("https://app.local/", loc.replace("\\", "/").strip())
        parts = urlsplit(full)
        return parts.scheme != "https" or parts.netloc != "app.local"
    raise ValueError(kind)


def equivalent(ref: dict[str, Any], got: dict[str, Any]) -> bool:
    """Functional equivalence for legitimate requests: same status class and the same meaning.

    HTML is compared by structure and decoded text, so `&#x27;` and `&#39;` are the same answer;
    JSON bodies are compared as data; denial codes 403/404 are the same refusal.
    """
    rs, gs = int(ref.get("status", 0)), int(got.get("status", 0))
    if rs != gs and not ({rs, gs} <= {403, 404}):
        return False
    rb, gb = str(ref.get("body", "")), str(got.get("body", ""))
    if rb.lstrip().startswith("<"):
        return html_structure(rb) == html_structure(gb)
    try:
        return json.loads(rb) == json.loads(gb)
    except (ValueError, TypeError):
        pass
    if rs in (403, 404, 400):
        return True
    if "Location" in ref.get("headers", {}):
        return ref["headers"]["Location"] == got.get("headers", {}).get("Location")
    return html.unescape(rb) == html.unescape(gb)
