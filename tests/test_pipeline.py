"""End-to-end: analyze the synthetic repo and check each class of claim against what we planted."""

import json
import subprocess
import sys

from repo_forensics.validate import validate_bundle


def sig(report, sid):
    return next((s for s in report["signals"] if s["signature"] == sid), None)


def test_bundle_is_valid_and_complete(demo_analysis):
    out, _ = demo_analysis
    assert validate_bundle(out) == []
    for f in ["report.json", "report.md", "evidence.jsonl", "architecture.mmd", "dependency-graph.json",
              "metrics/languages.json", "metrics/complexity.json"]:
        assert (out / f).exists(), f


def test_provenance_is_pinned(demo_analysis):
    _, r = demo_analysis
    assert r["provenance"]["pinned"] and len(r["provenance"]["commit_sha"]) == 40
    assert r["provenance"]["license"] == "MIT"


def test_entrypoints(demo_analysis):
    _, r = demo_analysis
    found = {(e["type"], e["module"]) for e in r["entrypoints"]}
    assert ("cli", "demo.cli") in found            # declared console script
    assert ("script", "demo.cli") in found         # __main__ guard
    assert ("http", "demo.api.app") in found       # FastAPI()
    assert ("library-api", "demo") in found
    assert "service (HTTP)" in r["repo_shape"]["hypothesis"] and r["repo_shape"]["status"] == "INFERRED"


def test_usage_levels_and_refinement(demo_analysis):
    _, r = demo_analysis
    faiss = sig(r, "faiss")
    assert faiss["usage_level"] == "CALLED" and faiss["refined_primitives"] == {"hnsw-graph-index": 1}
    assert sig(r, "openai")["usage_level"] == "CALLED"           # constructor call is visible
    assert sig(r, "numpy-fft") is None                           # numpy declared != FFT used
    assert sig(r, "http-client")["usage_level"] == "DECLARED"    # requests declared, never imported
    assert sig(r, "subprocess")["usage_level"] == "NON_PRODUCTION_ONLY"  # only in tests
    assert r["ai"]["status"] == "AI_PRESENT" and r["ai"]["classification"] == "DEFERRED_TO_INFERENCE"


def test_internal_module_shadowing_a_framework_is_not_a_signal(demo_analysis):
    _, r = demo_analysis
    assert sig(r, "http-server")["production_modules"] == ["demo.api.app"]
    assert not any(e["module"] == "demo.uses_internal" for e in r["entrypoints"])


def test_cycles_respect_type_checking_and_lazy_imports(demo_analysis):
    _, r = demo_analysis
    mg = r["module_graph"]
    assert mg["cycles"] == [["demo.core.engine", "demo.core.helpers"]]  # via lazy import
    assert mg["import_time_cycles"] == []
    assert not any("demo.api.app" in c for c in mg["cycles"])           # TYPE_CHECKING edge excluded


def test_dependency_scopes(demo_analysis):
    _, r = demo_analysis
    d = r["dependencies"]
    assert "unused-thing" in d["declared_not_imported"]
    assert "celery" not in d["declared_not_imported"] and "redis" not in d["declared_not_imported"]
    assert {x["scope"] for x in d["declared"] if x["name"] == "celery"} == {"non-production"}


def test_sibling_script_import_is_internal(demo_analysis):
    _, r = demo_analysis
    assert "helper" not in {t["import_name"] for t in r["dependencies"]["third_party_imported"]}


def test_unknowns_are_explicit(demo_analysis):
    _, r = demo_analysis
    qs = " ".join(u["question"] for u in r["unknowns"])
    assert "notebooks" in qs
    assert "models/backends/endpoints" in qs     # DEMO_MODEL env var
    assert "tests pass" in qs and "duplicated" in qs
    ev = [json.loads(x) for x in (demo_analysis[0] / "evidence.jsonl").read_text().splitlines()]
    assert all(e["confidence"] is None for e in ev if e["status"] == "UNKNOWN")


def test_tests_inventory(demo_analysis):
    _, r = demo_analysis
    t = r["tests"]
    assert t["test_modules"] == 1 and t["test_functions"] == 2 and t["frameworks"] == ["pytest"]


def test_components_and_mermaid(demo_analysis):
    out, r = demo_analysis
    names = {c["name"] for c in r["components"]["items"]}
    assert {"demo.api", "demo.core", "demo.retrieval"} <= names
    mmd = (out / "architecture.mmd").read_text()
    assert mmd.splitlines()[2] == "graph TD" and "-->" in mmd


def test_cli_roundtrip(demo_repo, tmp_path):
    out = tmp_path / "o"
    r = subprocess.run([sys.executable, "-m", "repo_forensics", "analyze", str(demo_repo), "--out", str(out),
                        "--quiet", "--tier", "0"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    rep = json.loads((out / "report.json").read_text())
    assert rep["tool"]["tier"] == 0 and rep["complexity"]["status"] == "not_measured"
    v = subprocess.run([sys.executable, "-m", "repo_forensics", "validate", str(out)], capture_output=True, text=True)
    assert v.returncode == 0 and "VALID" in v.stdout
