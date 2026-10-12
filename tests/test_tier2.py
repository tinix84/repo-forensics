"""Tier 2 end to end on a tiny repository. Needs network for wheel installs: opt in with RF_TIER2_TESTS=1."""

import json
import os
import sys

import pytest

from repo_forensics.analyze import run
from repo_forensics.validate import validate_bundle

from .conftest import write_repo

pytestmark = pytest.mark.skipif(os.environ.get("RF_TIER2_TESTS") != "1" or sys.version_info < (3, 12),
                                reason="set RF_TIER2_TESTS=1 (needs network, ~1 min, Python >= 3.12)")

REPO = {
    "pyproject.toml": '[project]\nname = "tdemo"\nversion = "0"\ndependencies = []\n'
                      '[project.scripts]\ntdemo = "pkg.cli:main"\n',
    "pkg/__init__.py": "REG = {}\n\ndef register(f):\n    REG[f.__name__] = f\n    return f\n",
    "pkg/handlers.py": "from dataclasses import dataclass\nfrom pkg import register\n\n\n@register\ndef hello():\n"
                       "    return 'hi'\n\n\ndef truly_dead():\n    return 1\n\n\n@dataclass\nclass Box:\n    x: int = 0\n\n"
                       "    def __post_init__(self):\n        self.x += 1\n",
    "pkg/plugins/__init__.py": "",
    "pkg/plugins/extra.py": "def run():\n    return 42\n",
    "pkg/cli.py": "import importlib\nimport sys\n\nimport pkg.handlers\nfrom pkg import REG\n\n\ndef main():\n"
                  "    if '--help' in sys.argv:\n        importlib.import_module('pkg.plugins.extra')\n"
                  "    print(REG['hello']())\n",
    "tests/test_x.py": "import pkg.handlers\nfrom pkg import REG\n\n\ndef test_hello():\n    assert REG['hello']() == 'hi'\n"
                       "    assert pkg.handlers.Box().x == 1\n",
}


@pytest.fixture(scope="module")
def tier2(tmp_path_factory):
    repo = write_repo(tmp_path_factory.mktemp("t2repo"), REPO)
    out = tmp_path_factory.mktemp("t2out")
    return out, run(str(repo), out, tier=2)


def evidence(out):
    return [json.loads(x) for x in (out / "evidence.jsonl").read_text().splitlines()]


def test_run_completes_and_validates(tier2):
    out, r = tier2
    assert validate_bundle(out) == []
    assert r["tool"]["tier"] == 2 and r["dynamic"]["status"] == "ok"
    t = r["dynamic"]["tests"]
    assert t["ran"] and t["tests"] == 1 and t["failures"] == 0 and t["coverage_percent"] > 0
    assert r["dynamic"]["isolation"]["container"] is False          # stated, not hidden


def test_execution_refutes_static_dead_code_claim(tier2):
    out, _ = tier2
    dead = {e["data"]["symbol"]: e for e in evidence(out) if e["kind"] == "fusion.dead_code"}
    assert dead["hello"]["data"]["verdict"] == "refuted" and dead["hello"]["status"] == "CONFIRMED"
    assert dead["truly_dead"]["data"]["verdict"] in ("likely-dead", "possibly-dead")
    assert dead["truly_dead"]["status"] in ("SUPPORTED", "INFERRED")  # absence of execution never CONFIRMS deadness


def test_runtime_loading_resolves_static_orphan(tier2):
    out, r = tier2
    loaded = [x["module"] for x in r["fusion"]["rules"]["reachability"]["orphans_loaded_at_runtime"]]
    assert "pkg.plugins.extra" in loaded


def test_generated_code_is_not_a_dispatcher(tier2):
    _, r = tier2
    assert not any(d["dispatcher"] == "pkg" for d in r["fusion"]["rules"]["coupling"]["external_dispatchers"])
