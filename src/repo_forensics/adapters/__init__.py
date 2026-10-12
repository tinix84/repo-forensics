"""Tool adapters: run an external analyzer, record exactly how, and normalize its findings.

A finding is a fact about the *tool's output* ("ruff reports F401 at x.py:3"). Whether it is
true about the code is decided later, by fusion with independent evidence.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class Finding:
    tool: str
    rule: str
    message: str
    file: str | None
    line: int | None
    level: str = "warning"  # tool's own severity
    confidence: float | None = None  # tool's own confidence, 0..1, when it reports one
    symbol: str | None = None
    kind: str | None = None  # e.g. vulture's 'function', 'import'
    extra: dict = field(default_factory=dict)


@dataclass
class ToolRun:
    tool: str
    version: str | None
    tier: int
    question: str
    command: list[str]
    status: str  # ok | failed | skipped | timeout
    exit_code: int | None = None
    duration_s: float | None = None
    note: str | None = None
    findings: list[Finding] = field(default_factory=list)

    def summary(self) -> dict:
        d = asdict(self)
        d.pop("findings")
        d["findings"] = len(self.findings)
        return d


def tool_version(cmd: list[str]) -> str | None:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = (r.stdout or r.stderr).strip().splitlines()
    return out[0][:80] if out else None


def available(exe: str) -> bool:
    return shutil.which(exe) is not None


def run_cmd(cmd: list[str], cwd: Path, timeout: int, env: dict | None = None) -> tuple[int | None, str, str, float, bool]:
    """Run without a shell; returns (exit, stdout, stderr, seconds, timed_out)."""
    t0 = time.monotonic()
    try:
        r = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env if env is not None else dict(os.environ)
        )
        return r.returncode, r.stdout, r.stderr, time.monotonic() - t0, False
    except subprocess.TimeoutExpired as e:
        return None, e.stdout or "", e.stderr or "", time.monotonic() - t0, True


def rel(path: str | None, root: Path) -> str | None:
    if not path:
        return None
    p = path.replace("file://", "")
    try:
        return str(Path(p).resolve().relative_to(root.resolve())).replace(os.sep, "/")
    except ValueError:
        return p.lstrip("./")
