"""Validate an analysis bundle: schemas plus the cross-file rules that keep facts and inferences apart."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

from jsonschema import Draft202012Validator

_SCHEMAS = resources.files("repo_forensics") / "schemas"


def _schema(name: str) -> Draft202012Validator:
    return Draft202012Validator(json.loads((_SCHEMAS / name).read_text(encoding="utf-8")))


def validate_bundle(out_dir: Path) -> list[str]:
    out_dir = Path(out_dir)
    errors: list[str] = []
    rp = out_dir / "report.json"
    ep = out_dir / "evidence.jsonl"
    if not rp.exists() or not ep.exists():
        return [f"missing report.json or evidence.jsonl in {out_dir}"]
    report = json.loads(rp.read_text(encoding="utf-8"))
    for e in _schema("report.schema.json").iter_errors(report):
        errors.append(f"report.json: {'/'.join(map(str, e.path))}: {e.message}")
    ev_schema = _schema("evidence.schema.json")
    ids: dict[str, dict] = {}
    from .render import digest
    raw_lines = ep.read_text(encoding="utf-8").splitlines()
    if report.get("evidence_digest") != digest(raw_lines):
        errors.append("evidence.jsonl does not match report.json evidence_digest (modified or mixed bundles)")
    for n, line in enumerate(raw_lines, 1):
        item = json.loads(line)
        for e in ev_schema.iter_errors(item):
            errors.append(f"evidence.jsonl:{n}: {e.message}")
        if item.get("id") in ids:
            errors.append(f"evidence.jsonl:{n}: duplicate id {item['id']}")
        ids[item.get("id")] = item

    def walk(o, where="report.json"):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "evidence_id" and v is not None and v not in ids:
                    errors.append(f"{where}: dangling evidence_id {v}")
                walk(v, where)
        elif isinstance(o, list):
            for x in o:
                walk(x, where)
    walk(report)

    hp = out_dir / "hypotheses.json"
    if hp.exists():
        hyp = json.loads(hp.read_text(encoding="utf-8"))
        for e in _schema("hypotheses.schema.json").iter_errors(hyp):
            errors.append(f"hypotheses.json: {'/'.join(map(str, e.path))}: {e.message}")
        if hyp.get("commit_sha") != report["provenance"].get("commit_sha"):
            errors.append("hypotheses.json: commit_sha does not match report.json (stale inference?)")
        if hyp.get("evidence_digest") != report.get("evidence_digest"):
            errors.append("hypotheses.json: evidence_digest does not match report.json — evidence ids may now "
                          "point to different facts; re-derive the inferences from the current report")
        comp_names = {c["name"] for c in report["components"]["items"]}
        for c in hyp.get("components", []):
            if c.get("name") not in comp_names:
                errors.append(f"hypotheses.json: component '{c.get('name')}' is not in report.json")
            for i in c.get("evidence_ids", []):
                if i not in ids:
                    errors.append(f"hypotheses.json: component {c.get('name')}: unknown evidence id {i}")
                elif ids[i].get("kind") == "component" and ids[i].get("data", {}).get("name") != c.get("name"):
                    errors.append(f"hypotheses.json: component {c.get('name')} cites {i}, which describes "
                                  f"component {ids[i].get('data', {}).get('name')}")
            if c.get("status") != "UNKNOWN" and not c.get("files_read"):
                errors.append(f"hypotheses.json: component {c.get('name')}: responsibility claimed without files_read")
        for h in hyp.get("architecture_hypotheses", []):
            for i in h.get("evidence_ids", []) + h.get("counter_evidence_ids", []):
                if i not in ids:
                    errors.append(f"hypotheses.json: {h.get('id')}: unknown evidence id {i}")
            if not h.get("counter_evidence_ids") and not h.get("counter_evidence_notes"):
                errors.append(f"hypotheses.json: {h.get('id')}: no counter-evidence recorded "
                              "(state what was searched for, even if nothing was found)")
            unk = [i for i in h.get("evidence_ids", []) if ids.get(i, {}).get("status") == "UNKNOWN"]
            if unk:
                errors.append(f"hypotheses.json: {h.get('id')}: cites UNKNOWN evidence {unk} as support")
        sigs = {s["signature"] for s in report["signals"]}
        for r in hyp.get("primitive_roles", []):
            if r.get("signature") not in sigs:
                errors.append(f"hypotheses.json: primitive role for unknown signature {r.get('signature')}")
            if r.get("role") == "CENTRAL":
                lvl = next((s["usage_level"] for s in report["signals"] if s["signature"] == r.get("signature")), None)
                if lvl != "CALLED":
                    errors.append(f"hypotheses.json: {r.get('signature')} marked CENTRAL but usage level is {lvl}")
        ai_cls = hyp.get("ai_assessment", {}).get("classification")
        if report["ai"]["status"] == "NO_AI_SIGNATURE_FOUND" and ai_cls in ("AI_CORE", "AI_SUPPORTING"):
            if not hyp["ai_assessment"].get("evidence_ids"):
                errors.append("hypotheses.json: AI classified as present without evidence while no AI signature was found")
    return errors
