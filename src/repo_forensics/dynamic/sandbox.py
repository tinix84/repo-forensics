"""Tier 2: run the target's code in a disposable environment and record what actually happens.

Dynamic evidence is existential: "observed in this run, with these inputs". It can refute a
static claim ("never used") with one observation, but it cannot prove absence: code that did
not run in this run may still run elsewhere. Every claim therefore carries its run manifest.

Isolation in this implementation is process-level (fresh venv, scrubbed environment, CPU and
file-size limits, disposable copy of the source). It is NOT a container: network and the
filesystem outside the work directory are reachable. The report states this explicitly.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from collections import Counter
from importlib import resources
from pathlib import Path, PurePosixPath

from ..config import normalize_dist

TOOLS = ["pytest", "pytest-timeout", "coverage", "deptry", "mypy"]
TEST_GROUP = re.compile(r"(?i)^(dev|test|tests|testing)$")


def _limits():  # pragma: no cover - runs in the child process
    import resource

    resource.setrlimit(resource.RLIMIT_CPU, (1800, 1800))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class Sandbox:
    def __init__(self, analyzer, raw_dir: Path | None, budget_s: int = 1500):
        self.a = analyzer
        self.raw_dir = raw_dir
        self.budget = budget_s
        self.t0 = time.monotonic()
        self.work = Path(tempfile.mkdtemp(prefix="rf-tier2-"))
        self.src = self.work / "src"
        self.venv = self.work / "venv"
        self.probes = self.work / "probes"
        self.steps: list[dict] = []

    # ------------------------------------------------------------ plumbing
    def env(self, extra: dict | None = None) -> dict:
        roots = [str(self.src / r) if r else str(self.src) for r in self.a.roots]
        e = {
            "PATH": f"{self.venv / 'bin'}:/usr/bin:/bin",
            "HOME": str(self.work / "home"),
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "NO_COLOR": "1",
            "PYTHONPATH": os.pathsep.join([*roots, str(self.probes)]),
            "RF_ROOT": str(self.src),
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
        }
        e.update(extra or {})
        return e

    def run(self, name: str, cmd: list[str], timeout: int, cwd: Path | None = None, env: dict | None = None) -> dict:
        left = self.budget - (time.monotonic() - self.t0)
        if left < 10:
            step = {"step": name, "command": cmd, "status": "skipped", "note": "time budget exhausted"}
            self.steps.append(step)
            return step
        t = time.monotonic()
        try:
            r = subprocess.run(
                cmd,
                cwd=cwd or self.src,
                env=env or self.env(),
                capture_output=True,
                text=True,
                timeout=min(timeout, int(left)),
                preexec_fn=_limits,
            )
            step = {
                "step": name,
                "command": [str(c) for c in cmd],
                "exit": r.returncode,
                "status": "ok",
                "duration_s": round(time.monotonic() - t, 1),
                "stdout_tail": r.stdout[-600:],
                "stderr_tail": r.stderr[-600:],
            }
        except subprocess.TimeoutExpired:
            step = {
                "step": name,
                "command": [str(c) for c in cmd],
                "status": "timeout",
                "duration_s": round(time.monotonic() - t, 1),
            }
        self.steps.append(step)
        return step

    def save_raw(self, src: Path, name: str) -> None:
        if self.raw_dir and src.exists():
            self.raw_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, self.raw_dir / name)

    # ------------------------------------------------------------ phases
    def prepare(self) -> None:
        for f in self.a.files:
            dst = self.src / f
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.a.acq.root / f, dst)
        (self.work / "home").mkdir()
        self.probes.mkdir()
        pkg = resources.files("repo_forensics.dynamic") / "probes"
        for name in ("rf_monitor.py", "rf_entry_probe.py", "rf_pytest_callgraph.py"):
            (self.probes / name).write_text((pkg / name).read_text(encoding="utf-8"), encoding="utf-8")
        self.run("create venv", [sys.executable, "-m", "venv", str(self.venv)], 120, cwd=self.work)

    def requirements(self) -> list[str]:
        own = {normalize_dist(m["name"]) for m in self.a.metas if m.get("name")}
        reqs = []
        for d in self.a.declared:
            scope = d.scope
            wanted = (
                scope == "runtime"
                or scope == "dev"
                or (scope.startswith("optional:") and TEST_GROUP.match(scope.split(":", 1)[1]))
            )
            if not wanted or d.name in own:
                continue
            raw = d.raw if ("{" not in d.raw and not d.raw.startswith(("-", "git+", "http"))) else d.name
            raw = re.sub(r"\[([^\]]*)\]", lambda m: "" if any(o in own for o in m.group(1).split(",")) else m.group(0), raw)
            reqs.append(raw)
        return sorted(set(reqs))

    def install(self) -> dict:
        reqs = self.requirements()
        pip = [str(self.venv / "bin" / "python"), "-m", "pip", "install", "--only-binary", ":all:", "-q"]
        tools = self.run("install analysis tools", [*pip, *TOOLS], 600)
        bulk = self.run("install dependencies (wheels only)", [*pip, *reqs], 900) if reqs else {"status": "ok", "exit": 0}
        failed = []
        if bulk.get("exit") not in (0, None) or bulk.get("status") != "ok":
            for r in reqs[:80]:
                s = self.run(f"install {r}", [*pip, r], 300)
                if s.get("exit") != 0:
                    failed.append(r)
        return {
            "requested": reqs,
            "only_binary": True,
            "failed": failed,
            "tools_ok": tools.get("exit") == 0,
            "deps_ok": not failed,
        }

    def probe_entries(self) -> list[dict]:
        out = []
        py = str(self.venv / "bin" / "python")
        specs = [
            (e["spec"], e.get("name") or e["spec"])
            for e in self.a.entries
            if e["type"] in ("cli", "ui") and e.get("spec") and e.get("module") in self.a.prod
        ]
        for e in self.a.entries:
            if e["type"] == "library-api" and e.get("module"):
                specs.append((e["module"], e["module"]))
        for spec, prog in specs[:8]:
            tag = re.sub(r"\W+", "_", spec)
            res = self.work / f"entry_{tag}.json"
            self.run(f"entry probe {spec}", [py, str(self.probes / "rf_entry_probe.py"), str(res), spec, prog], 120)
            status = res.with_suffix(".json.status").read_text() if res.with_suffix(".json.status").exists() else "no output"
            data = json.loads(res.read_text()) if res.exists() else {}
            self.save_raw(res, f"entry_{tag}.json")
            out.append(
                {"spec": spec, "status": status, "loaded_files": data.get("loaded_files", []), "edges": data.get("edges", [])}
            )
        return out

    def run_tests(self) -> dict:
        if not self.a.tests:
            return {"ran": False, "reason": "no test modules"}
        py = str(self.venv / "bin" / "python")
        cg = self.work / "callgraph_tests.json"
        cov = self.work / "cov.data"
        env = self.env({"RF_CALLGRAPH_OUT": str(cg)})
        step = self.run(
            "tests under coverage + call graph",
            [
                py,
                "-m",
                "coverage",
                "run",
                f"--data-file={cov}",
                "--source=.",
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "-p",
                "rf_pytest_callgraph",
                "--timeout=120",
                f"--junitxml={self.work / 'junit.xml'}",
            ],
            1200,
            env=env,
        )
        self.run(
            "coverage json",
            [py, "-m", "coverage", "json", f"--data-file={cov}", "-o", str(self.work / "coverage.json"), "--ignore-errors"],
            120,
            env=env,
        )
        for f, n in (
            (cg, "callgraph_tests.json"),
            (self.work / "coverage.json", "coverage.json"),
            (self.work / "junit.xml", "junit.xml"),
        ):
            self.save_raw(f, n)
        res = {"ran": True, "exit": step.get("exit"), "status": step["status"]}
        junit = self.work / "junit.xml"
        if junit.exists():
            try:
                root = ET.parse(junit).getroot()
                suites = [root] if root.tag == "testsuite" else list(root)
                for k in ("tests", "failures", "errors", "skipped"):
                    res[k] = sum(int(s.get(k, 0)) for s in suites)
            except ET.ParseError:
                res["junit"] = "unparseable"
        res["callgraph"] = json.loads(cg.read_text()) if cg.exists() else None
        covj = self.work / "coverage.json"
        res["coverage"] = json.loads(covj.read_text()) if covj.exists() else None
        return res

    def deptry(self) -> dict:
        py = str(self.venv / "bin" / "python")
        out = self.work / "deptry.json"
        step = self.run("deptry (installed environment)", [py, "-m", "deptry", ".", "--json-output", str(out)], 300)
        self.save_raw(out, "deptry.json")
        if not out.exists():
            return {"status": "failed", "note": step.get("stderr_tail", "")[-200:]}
        return {"status": "ok", "issues": json.loads(out.read_text())}

    def execute(self) -> dict:
        try:
            self.prepare()
            install = self.install()
            entries = self.probe_entries()
            tests = self.run_tests()
            dep = self.deptry()
            my = self.mypy_full()
        finally:
            shutil.rmtree(self.work, ignore_errors=True)
        ok = install["tools_ok"] and (tests.get("ran") is False or tests.get("status") == "ok")
        return {
            "status": "ok" if ok and install["deps_ok"] else ("partial" if install["tools_ok"] else "failed"),
            "isolation": {
                "level": "process",
                "container": False,
                "network": "available",
                "environment": "scrubbed (no inherited variables or credentials)",
                "limits": "CPU 1800 s per process, files 2 GB, no core dumps",
                "source": "disposable copy",
                "note": "demo-grade isolation; not safe for hostile code",
            },
            "python": sys.version.split()[0],
            "install": install,
            "entry_probes": entries,
            "tests": tests,
            "deptry": dep,
            "mypy": my,
            "steps": self.steps,
            "elapsed_s": round(time.monotonic() - self.t0, 1),
        }

    def mypy_full(self) -> dict:
        """mypy with full JSON capture (one object per line)."""
        py = str(self.venv / "bin" / "python")
        targets = sorted(
            {str(PurePosixPath(self.a.path_of[t]).parent) for t in self.a.prod if self.a.fact_of[t].is_package and "." not in t}
        )
        if not targets:
            return {"status": "skipped", "note": "no top-level package"}
        out = self.work / "mypy.jsonl"
        cmd = [
            py,
            "-m",
            "mypy",
            *targets,
            "--ignore-missing-imports",
            "--no-error-summary",
            "-O",
            "json",
            "--cache-dir",
            str(self.work / "mypy_cache"),
        ]
        left = self.budget - (time.monotonic() - self.t0)
        if left < 30:
            self.steps.append({"step": "mypy", "status": "skipped", "note": "time budget exhausted"})
            return {"status": "skipped"}
        t = time.monotonic()
        with out.open("w") as fh:
            try:
                r = subprocess.run(
                    cmd,
                    cwd=self.src,
                    env=self.env(),
                    stdout=fh,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=min(600, int(left)),
                    preexec_fn=_limits,
                )
                status, code = "ok", r.returncode
            except subprocess.TimeoutExpired:
                status, code = "timeout", None
        self.steps.append(
            {
                "step": "mypy (installed environment)",
                "command": cmd,
                "status": status,
                "exit": code,
                "duration_s": round(time.monotonic() - t, 1),
            }
        )
        self.save_raw(out, "mypy.jsonl")
        by_file: Counter = Counter()
        codes: Counter = Counter()
        for ln in out.read_text().splitlines():
            try:
                d = json.loads(ln)
            except json.JSONDecodeError:
                continue
            if d.get("severity") == "error":
                by_file[d.get("file", "?")] += 1
                codes[d.get("code") or "?"] += 1
        return {
            "status": status,
            "exit": code,
            "errors": sum(by_file.values()),
            "by_file": dict(by_file),
            "by_code": dict(codes.most_common(10)),
        }


def module_of_path(analyzer) -> dict[str, str]:
    return {p: m for m, p in analyzer.path_of.items()}


def aggregate_edges(edges: list, path_to_module: dict) -> tuple[Counter, Counter]:
    """Function edges ('path::qualname') -> module edges; external callers kept as '<external:x>'."""
    mod_edges: Counter = Counter()
    external: Counter = Counter()
    for src, dst, n in edges:
        dpath = dst.split("::", 1)[0]
        dmod = path_to_module.get(dpath)
        if not dmod:
            continue
        if src.startswith("<generated:"):
            continue  # runtime-generated code (e.g. dataclass methods) belongs to its own module, not a dispatcher
        if src.startswith("<external:"):
            external[(src, dmod)] += n
            continue
        smod = path_to_module.get(src.split("::", 1)[0])
        if smod and smod != dmod:
            mod_edges[(smod, dmod)] += n
    return mod_edges, external


def run_tier2(analyzer, raw_dir: Path | None) -> dict:
    return Sandbox(analyzer, raw_dir).execute()


__all__ = ["run_tier2", "aggregate_edges", "module_of_path"]
