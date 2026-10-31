"""The runtime a generated service is written against: a database, a document store, a shell.

This file is copied fresh into the sandbox for every grading run, so a patch cannot change it.
Nothing here touches the real system: the database is in memory, files live in a temporary
directory, and the shell is simulated (it parses a command line the way /bin/sh would and records
what *would* have run, without running anything).
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any

WORLD: dict[str, Any] = {}
ROOT = Path(os.environ.get("DRG_ROOT", "."))
DOCS = ROOT / "docs"


def connect() -> sqlite3.Connection:
    """A fresh in-memory database with the world's tables."""
    conn = sqlite3.connect(":memory:")
    for name, table in WORLD.get("tables", {}).items():
        cols = table["columns"]
        conn.execute(f"CREATE TABLE {name} ({', '.join(cols)})")
        conn.executemany(f"INSERT INTO {name} VALUES ({', '.join('?' for _ in cols)})", table["rows"])
    return conn


def records(name: str) -> dict[str, dict[str, Any]]:
    """A keyed collection (for example invoices) as a dict of dicts; a copy per call."""
    return {k: dict(v) for k, v in WORLD.get("records", {}).get(name, {}).items()}


def save_record(name: str, key: str, value: dict[str, Any]) -> None:
    WORLD.setdefault("writes", []).append({"collection": name, "key": key, "value": value})


# ---------------------------------------------------------------------- the simulated shell
class Shell:
    """Records commands instead of running them.

    `run(command_line)` behaves like `sh -c`: commands are separated by ; & && || | and newlines,
    $(...) and backticks run (also inside double quotes), single quotes are literal. `run_args([...])`
    runs exactly one program with exactly these arguments (no shell). The simulated `ping` and
    `traceroute` read options like the real ones: a word starting with '-' before `--` is an option.
    """

    def __init__(self) -> None:
        self.log: list[list[str]] = []

    def run(self, command_line: str) -> str:
        out = [self._exec(words) for words in self._parse(command_line) if words]
        return "\n".join(out)

    def run_args(self, args: list[str]) -> str:
        if not args or not all(isinstance(a, str) for a in args):
            raise TypeError("run_args needs a non-empty list of strings")
        return self._exec(list(args))

    def _substitute(self, s: str, i: int, closer: str) -> tuple[str, int]:
        """Run a command substitution whose body starts at s[i]; return its output and the next index."""
        depth, j = 1, i
        while j < len(s):
            if closer == ")" and s.startswith("$(", j):
                depth += 1
                j += 2
                continue
            if s[j] == closer:
                depth -= 1
                if depth == 0:
                    break
            j += 1
        inner = s[i:j]
        return (self.run(inner) if inner.strip() else ""), j + 1

    def _parse(self, s: str) -> list[list[str]]:
        commands: list[list[str]] = []
        words: list[str] = []
        cur: list[str] = []
        quote: str | None = None
        started = False
        i = 0

        def end_word() -> None:
            nonlocal cur, started
            if cur or started:
                words.append("".join(cur))
            cur, started = [], False

        while i < len(s):
            ch = s[i]
            if quote == "'":
                if ch == "'":
                    quote = None
                else:
                    cur.append(ch)
                i += 1
                continue
            if s.startswith("$(", i):
                out, i = self._substitute(s, i + 2, ")")
                cur.append(out.split()[0] if out.split() else "")
                started = True
                continue
            if ch == "`":
                out, i = self._substitute(s, i + 1, "`")
                cur.append(out.split()[0] if out.split() else "")
                started = True
                continue
            if quote == '"':
                if ch == '"':
                    quote = None
                else:
                    cur.append(ch)
                i += 1
                continue
            if ch in "'\"":
                quote, started = ch, True
            elif ch in ";&|\n":
                end_word()
                commands.append(words)
                words = []
                while i + 1 < len(s) and s[i + 1] in "&|":
                    i += 1
            elif ch.isspace():
                end_word()
            else:
                cur.append(ch)
            i += 1
        end_word()
        commands.append(words)
        return commands

    def _exec(self, words: list[str]) -> str:
        self.log.append(words)
        prog, rest = words[0], words[1:]
        if prog in ("ping", "traceroute"):
            hosts, end_of_options = [], False
            for w in rest:
                if w == "--":
                    end_of_options = True
                elif w.startswith("-") and not end_of_options:
                    continue
                else:
                    hosts.append(w)
            host = hosts[-1] if hosts else "?"
            return f"{prog.upper()} {host}: reachable"
        return f"{prog}: ran"


shell = Shell()


def reset(world: dict[str, Any]) -> None:
    """Called by the runner before every request."""
    WORLD.clear()
    WORLD.update(world)
    WORLD["writes"] = []
    shell.log.clear()
