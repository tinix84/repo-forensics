"""The validator enforces the separation between measured facts and LLM inferences."""

import json
import shutil

from repo_forensics.validate import validate_bundle


def _copy(demo_analysis, tmp_path):
    out, report = demo_analysis
    dst = tmp_path / "bundle"
    shutil.copytree(out, dst)
    return dst, report


def good_hypotheses(report):
    comp = report["components"]["items"][0]
    faiss = next(s for s in report["signals"] if s["signature"] == "faiss")
    return {
        "schema_version": "0.1.0",
        "commit_sha": report["provenance"]["commit_sha"],
        "evidence_digest": report["evidence_digest"],
        "components": [{"name": comp["name"], "responsibility": "Owns the core run loop.", "status": "INFERRED",
                        "confidence": 0.7, "evidence_ids": [comp["evidence_id"]], "files_read": ["src/demo/core/engine.py"]}],
        "architecture_hypotheses": [{
            "id": "HY-01", "pattern": "layered", "claim": "api depends on core which depends on retrieval",
            "status": "INFERRED", "confidence": 0.6, "evidence_ids": [comp["evidence_id"]],
            "counter_evidence_ids": [], "counter_evidence_notes": ["searched for retrieval -> api imports: none"],
            "how_to_falsify": "Find an import from demo.retrieval into demo.api."}],
        "primitive_roles": [{"signature": "faiss", "role": "CENTRAL", "evidence_ids": [faiss["evidence_id"]],
                             "rationale": "called on the search path"}],
        "ai_assessment": {"classification": "AI_SUPPORTING", "evidence_ids": [], "rationale": "x"},
        "unknowns": [],
    }


def test_good_hypotheses_validate(demo_analysis, tmp_path):
    dst, report = _copy(demo_analysis, tmp_path)
    (dst / "hypotheses.json").write_text(json.dumps(good_hypotheses(report)))
    assert validate_bundle(dst) == []


def test_validator_rejects_unsupported_inference(demo_analysis, tmp_path):
    dst, report = _copy(demo_analysis, tmp_path)
    h = good_hypotheses(report)
    h["architecture_hypotheses"][0]["counter_evidence_notes"] = []          # no counter-evidence
    h["architecture_hypotheses"][0]["evidence_ids"] = ["EV-9999"]           # dangling id
    h["primitive_roles"].append({"signature": "http-client", "role": "CENTRAL", "evidence_ids": [],
                                 "rationale": "declared only"})             # CENTRAL but not CALLED
    h["components"][0]["files_read"] = []                                   # claim without reading code
    h["architecture_hypotheses"][0]["status"] = "CONFIRMED"                 # inference cannot be CONFIRMED
    h["commit_sha"] = "0" * 40                                              # stale
    (dst / "hypotheses.json").write_text(json.dumps(h))
    errs = "\n".join(validate_bundle(dst))
    for needle in ["no counter-evidence", "EV-9999", "marked CENTRAL", "without files_read",
                   "'CONFIRMED' is not one of", "commit_sha does not match"]:
        assert needle in errs, needle


def test_validator_detects_dangling_report_reference(demo_analysis, tmp_path):
    dst, report = _copy(demo_analysis, tmp_path)
    r = json.loads((dst / "report.json").read_text())
    r["smells"].append({"rule": "x", "target": "y", "detail": "", "severity": "info", "evidence_id": "EV-9998"})
    (dst / "report.json").write_text(json.dumps(r))
    assert any("EV-9998" in e for e in validate_bundle(dst))


def test_stale_evidence_digest_is_rejected(demo_analysis, tmp_path):
    dst, report = _copy(demo_analysis, tmp_path)
    h = good_hypotheses(report)
    h["evidence_digest"] = "sha256:" + "0" * 32
    (dst / "hypotheses.json").write_text(json.dumps(h))
    assert any("evidence_digest does not match" in e for e in validate_bundle(dst))


def test_component_citing_another_components_evidence_is_rejected(demo_analysis, tmp_path):
    dst, report = _copy(demo_analysis, tmp_path)
    h = good_hypotheses(report)
    h["components"][0]["evidence_ids"] = [report["components"]["items"][1]["evidence_id"]]
    (dst / "hypotheses.json").write_text(json.dumps(h))
    assert any("which describes component" in e for e in validate_bundle(dst))


def test_tampered_evidence_is_detected(demo_analysis, tmp_path):
    dst, _ = _copy(demo_analysis, tmp_path)
    p = dst / "evidence.jsonl"
    p.write_text(p.read_text().replace("CONFIRMED", "SUPPORTED", 1))
    assert any("does not match report.json evidence_digest" in e for e in validate_bundle(dst))


def test_html_renders_inference_only_when_valid(demo_analysis, tmp_path):
    from repo_forensics.html import render_html
    dst, report = _copy(demo_analysis, tmp_path)
    page = render_html(dst).read_text()
    assert "No inference layer yet" in page and 'id="EV-0001"' in page
    h = good_hypotheses(report)
    (dst / "hypotheses.json").write_text(json.dumps(h))
    page = render_html(dst).read_text()
    assert "Owns the core run loop." in page and "No inference layer yet" not in page
    h["evidence_digest"] = "sha256:" + "0" * 32          # invalid -> inference must not be shown
    (dst / "hypotheses.json").write_text(json.dumps(h))
    assert "Owns the core run loop." not in render_html(dst).read_text()
