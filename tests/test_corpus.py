"""Corpus: cross-repository facts, shared primitives, role implementations, weakest-link status."""

import json
import shutil

import pytest

from repo_forensics.analyze import run
from repo_forensics.corpus import CorpusError, add, compare, weakest

from .conftest import FILES, write_repo

OTHER = {
    "pyproject.toml": '[project]\nname = "other"\nversion = "0"\ndependencies = ["hnswlib", "openai", "boto3"]\n',
    "other/__init__.py": "",
    "other/search.py": "import hnswlib\nfrom openai import OpenAI\nimport boto3\n\ndef s():\n"
                       "    hnswlib.Index('l2', 4)\n    OpenAI()\n    boto3.client('s3')\n",
}


def hypotheses(report, comp_name, roles, pattern_id, status="INFERRED", conf=0.7):
    comp = next(c for c in report["components"]["items"] if c["name"] == comp_name)
    return {
        "schema_version": "0.1.0", "commit_sha": report["provenance"]["commit_sha"],
        "evidence_digest": report["evidence_digest"],
        "components": [{"name": comp_name, "responsibility": "Searches vectors for queries.", "roles": roles,
                        "status": status, "confidence": conf, "evidence_ids": [comp["evidence_id"]],
                        "files_read": ["x.py"]}],
        "architecture_hypotheses": [{"id": "HY-01", "pattern_id": pattern_id, "pattern": pattern_id,
                                     "claim": "a claim long enough", "status": status, "confidence": conf,
                                     "evidence_ids": [comp["evidence_id"]], "counter_evidence_ids": [],
                                     "counter_evidence_notes": ["searched"], "how_to_falsify": "find something else"}],
        "primitive_roles": [], "ai_assessment": {"classification": "AI_SUPPORTING", "evidence_ids": [], "rationale": "r"},
        "unknowns": [],
    }


@pytest.fixture(scope="module")
def corpus(tmp_path_factory, demo_analysis):
    base = tmp_path_factory.mktemp("corpus")
    a_out, a_rep = demo_analysis
    a = base / "a"
    shutil.copytree(a_out, a)
    (a / "hypotheses.json").write_text(json.dumps(
        hypotheses(a_rep, "demo.retrieval", ["retrieval", "llm-provider-adapter"], "graph-rag", "SUPPORTED", 0.9)))
    other_repo = write_repo(tmp_path_factory.mktemp("other"), OTHER)
    b = base / "b"
    b_rep = run(str(other_repo), b)
    (b / "hypotheses.json").write_text(json.dumps(hypotheses(b_rep, "other.search", ["retrieval"], "rag")))
    c = base / "corpus"
    add(a, c)
    add(b, c)
    return c, compare(c)


def test_weakest_link():
    assert weakest("CONFIRMED", "SUPPORTED", "INFERRED") == "INFERRED"
    assert weakest("CONFIRMED", "UNKNOWN") == "UNKNOWN"


def test_shared_primitives_across_libraries(corpus):
    _, res = corpus
    row = next(r for r in res["primitives"] if r["primitive"] == "approximate-nearest-neighbor")
    assert row["shared"] and row["used_by"] == 2
    assert row["libraries_across_repos"] == ["faiss", "hnswlib"]       # same abstraction, different libraries
    assert next(r for r in res["primitives"] if r["primitive"] == "hosted-llm-inference")["shared"]


def test_facts_use_global_evidence_references(corpus):
    c, _ = corpus
    facts = [json.loads(x) for x in (c / "facts.jsonl").read_text().splitlines()]
    assert all("@" in ev and "#EV-" in ev for f in facts for ev in f["evidence"])
    assert {f["predicate"] for f in facts} >= {"uses_primitive", "has_component", "has_role", "exhibits_pattern"}


def test_role_implementation_is_filtered_by_vocabulary(corpus):
    _, res = corpus
    retrieval = next(r for r in res["roles"] if r["role"] == "retrieval")
    impl = {repo.split("/")[-1]: x["implementations"] for repo, x in retrieval["repos"].items()}
    other = next(v for k, v in impl.items() if k != "demo0" and "faiss" not in " ".join(v))
    assert any("hnswlib" in i for i in other)
    assert not any("boto3" in i or "openai" in i for i in other)    # S3/LLM clients do not implement retrieval
    assert retrieval["status"] == "INFERRED" and retrieval["differs"]


def test_pattern_family_takes_weakest_status(corpus):
    _, res = corpus
    fam = next(f for f in res["pattern_families"] if f["family"] == "rag")
    assert fam["members"] == ["graph-rag", "rag"] and fam["in_repos"] == 2 and fam["status"] == "INFERRED"


def test_similarity_and_page(corpus):
    c, res = corpus
    s = res["similarity"][0]
    assert 0 < s["jaccard"] < 1 and "approximate-nearest-neighbor" in s["shared"]
    page = (c / "compare.html").read_text()
    assert "Shared primitives" in page and 'id="ev-' in page


def test_corpus_rejects_unpinned_bundles(tmp_path):
    repo = write_repo(tmp_path / "r", FILES, git=False)
    out = tmp_path / "o"
    run(str(repo), out)
    with pytest.raises(CorpusError, match="pinned"):
        add(out, tmp_path / "c")


def test_invalid_hypotheses_are_dropped_not_ingested(tmp_path, demo_analysis):
    out, rep = demo_analysis
    b = tmp_path / "b"
    shutil.copytree(out, b)
    h = hypotheses(rep, "demo.retrieval", ["retrieval"], "rag")
    h["evidence_digest"] = "sha256:" + "0" * 32
    (b / "hypotheses.json").write_text(json.dumps(h))
    entry = add(b, tmp_path / "c")
    assert not entry["inference"] and entry["inference_rejected"]
