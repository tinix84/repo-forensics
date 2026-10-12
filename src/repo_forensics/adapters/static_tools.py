"""Tier 1 adapters: tools that only read source text. None of them imports or runs the target."""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import Finding, ToolRun, available, rel, run_cmd, tool_version
from .sarif import parse_sarif

# Correctness-oriented rules only. Security rules (ruff's S family) are deliberately excluded:
# they reimplement bandit, and two tools sharing an algorithm are not independent evidence.
RUFF_SELECT = "F,E9,B,PLE"
VULTURE_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+): (?P<msg>(?:unused|unreachable|redundant)[^(]*?)\s*\((?P<conf>\d+)% confidence"
)
VULTURE_KIND = re.compile(r"unused (attribute|class|function|import|method|property|variable)|unreachable code|redundant")


def ruff(root: Path, paths: list[str], timeout: int = 300) -> ToolRun:
    tr = ToolRun(
        "ruff",
        tool_version(["ruff", "--version"]),
        1,
        "correctness",
        ["ruff", "check", "--isolated", "--select", RUFF_SELECT, "--output-format", "sarif", "--exit-zero", "--no-cache", *paths],
        "skipped",
    )
    if not available("ruff"):
        tr.note = "ruff not installed"
        return tr
    code, out, err, dt, to = run_cmd(tr.command, root, timeout)
    tr.duration_s, tr.exit_code = round(dt, 2), code
    if to or code not in (0,):
        tr.status, tr.note = ("timeout" if to else "failed"), err[-300:]
        return tr
    tr.findings, _ = parse_sarif(out, root)
    tr.status = "ok"
    return tr


def vulture(root: Path, paths: list[str], timeout: int = 300) -> ToolRun:
    tr = ToolRun(
        "vulture",
        tool_version(["vulture", "--version"]),
        1,
        "dead-code",
        ["vulture", "--min-confidence", "60", *paths],
        "skipped",
    )
    if not available("vulture"):
        tr.note = "vulture not installed"
        return tr
    code, out, err, dt, to = run_cmd(tr.command, root, timeout)
    tr.duration_s, tr.exit_code = round(dt, 2), code
    if to or code not in (0, 1, 3):  # 3 = dead code found
        tr.status, tr.note = ("timeout" if to else "failed"), err[-300:]
        return tr
    for ln in out.splitlines():
        m = VULTURE_RE.match(ln.strip())
        if not m:
            continue
        msg = m.group("msg").strip()
        k = VULTURE_KIND.search(msg)
        kind = (k.group(1) or k.group(0).split()[0]) if k else "other"
        sym = re.search(r"'([^']+)'", msg)
        tr.findings.append(
            Finding(
                "vulture",
                f"unused-{kind}",
                msg,
                rel(m.group("file"), root),
                int(m.group("line")),
                confidence=int(m.group("conf")) / 100,
                symbol=sym.group(1) if sym else None,
                kind=kind,
            )
        )
    tr.status = "ok"
    return tr


def bandit(root: Path, paths: list[str], timeout: int = 600) -> ToolRun:
    tr = ToolRun(
        "bandit", tool_version(["bandit", "--version"]), 1, "security", ["bandit", "-r", *paths, "-f", "json", "-q"], "skipped"
    )
    if not available("bandit"):
        tr.note = "bandit not installed"
        return tr
    code, out, err, dt, to = run_cmd(tr.command, root, timeout)
    tr.duration_s, tr.exit_code = round(dt, 2), code
    if to or code not in (0, 1):
        tr.status, tr.note = ("timeout" if to else "failed"), err[-300:]
        return tr
    conf = {"LOW": 0.3, "MEDIUM": 0.6, "HIGH": 0.9}
    for r in json.loads(out or "{}").get("results", []):
        tr.findings.append(
            Finding(
                "bandit",
                r["test_id"],
                r["issue_text"],
                rel(r["filename"], root),
                r["line_number"],
                level=r["issue_severity"].lower(),
                confidence=conf.get(r["issue_confidence"]),
                symbol=r["test_name"],
                extra={"cwe": (r.get("issue_cwe") or {}).get("id")},
            )
        )
    tr.status = "ok"
    return tr
