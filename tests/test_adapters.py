"""Tier 1 adapters and the stdlib-only runtime monitor."""

import json
import shutil
import subprocess
import sys
import textwrap
from importlib import resources
from pathlib import Path

import pytest

from repo_forensics.adapters.sarif import parse_sarif
from repo_forensics.adapters.static_tools import VULTURE_KIND, VULTURE_RE


def test_vulture_line_format():
    m = VULTURE_RE.match("llm/cli.py:1553: unused function 'keys_list' (60% confidence)")
    assert m and m.group("file") == "llm/cli.py" and m.group("line") == "1553" and m.group("conf") == "60"
    assert VULTURE_KIND.search(m.group("msg")).group(1) == "function"
    assert VULTURE_RE.match("a.py:3: unreachable code after 'return' (100% confidence)")


def test_sarif_reader(tmp_path):
    sarif = {"runs": [{"tool": {"driver": {"name": "ruff", "version": "0.1"}}, "results": [
        {"ruleId": "F401", "level": "error", "message": {"text": "unused import"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": str(tmp_path / "pkg/a.py")},
                                             "region": {"startLine": 3}}}]}]}]}
    findings, version = parse_sarif(json.dumps(sarif), tmp_path)
    assert version == "0.1" and findings[0].rule == "F401" and findings[0].file == "pkg/a.py" and findings[0].line == 3


@pytest.mark.skipif(not all(shutil.which(t) for t in ("ruff", "vulture", "bandit")), reason="tier 1 tools not installed")
def test_tier1_tools_run_on_fixture(demo_analysis):
    _, r = demo_analysis
    status = {t["tool"]: t["status"] for t in r["toolchain"]}
    assert status == {"ruff": "ok", "vulture": "ok", "bandit": "ok"}
    assert r["tool"]["tier"] == 1 and r["fusion"]["rules"]["dead_code"]["status"] == "ok"
    assert r["dynamic"]["status"] == "not_run"


def test_runtime_monitor_records_callers(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "t.py").write_text(textwrap.dedent("""
        from dataclasses import dataclass
        def callee(): return 1
        def caller(): return callee()
        def hook(): return 2
        @dataclass
        class D:
            x: int = 0
            def __post_init__(self): hook()
    """))
    probes = resources.files("repo_forensics.dynamic") / "probes" / "rf_monitor.py"
    (tmp_path / "rf_monitor.py").write_text(probes.read_text())
    (tmp_path / "run.py").write_text("import sys; sys.path.insert(0, 'repo')\nimport rf_monitor\nrf_monitor.start()\n"
                                     "import t\nt.caller()\nt.D()\nrf_monitor.stop_and_dump('o.json')\n")
    env = {"RF_ROOT": str(repo), "PATH": "/usr/bin:/bin"}
    subprocess.run([sys.executable, "run.py"], cwd=tmp_path, env=env, check=True)
    edges = {(s, d) for s, d, _ in json.loads((tmp_path / "o.json").read_text())["edges"]}
    assert ("t.py::caller", "t.py::callee") in edges                    # caller is frame.f_back, not the callee itself
    assert ("<generated:t>", "t.py::D.__post_init__") in edges           # dataclass __init__ is generated code
    assert not any(s.startswith("<frozen") or d.startswith("<") for s, d in edges)
    assert Path(tmp_path / "o.json").exists()
