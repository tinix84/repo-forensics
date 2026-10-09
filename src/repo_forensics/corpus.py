"""Corpus: many validated bundles -> one fact table -> cross-repository comparisons.

Facts are triples with global evidence references (`owner/repo@sha12#EV-0042`), so a
cross-repo statement can cite evidence from several bundles. A comparison inherits the
weakest status of its inputs: comparing two inferences yields an inference.
"""

from __future__ import annotations

import json
import re
import shutil
from collections import defaultdict
from datetime import UTC, datetime
from itertools import combinations
from pathlib import Path

from .config import load_config
from .validate import validate_bundle

STATUS_RANK = {"CONFIRMED": 3, "SUPPORTED": 2, "INFERRED": 1, "UNKNOWN": 0}
LEVEL_RANK = {"NON_PRODUCTION_ONLY": 0, "DECLARED": 1, "IMPORTED": 2, "CALLED": 3}
BUNDLE_FILES = ("report.json", "evidence.jsonl", "hypotheses.json", "report.html", "architecture.mmd")
COMPARED_CATEGORIES = ("ai", "algorithm", "storage")


class CorpusError(RuntimeError):
    pass


def weakest(*statuses: str) -> str:
    return min(statuses, key=lambda s: STATUS_RANK.get(s, 0)) if statuses else "UNKNOWN"


def repo_id(report: dict, fallback: str) -> str:
    url = report["provenance"].get("url") or ""
    m = re.search(r"github\.com[/:]([^/]+/[^/.]+?)(?:\.git)?/?$", url)
    return m.group(1) if m else fallback


def _ref(repo: str, sha: str | None) -> str:
    return f"{repo}@{(sha or 'unpinned')[:12]}"


# ------------------------------------------------------------------ ingest
def add(bundle: Path, corpus: Path) -> dict:
    """Validate and copy a bundle into the corpus (one entry per repository: latest wins)."""
    bundle, corpus = Path(bundle), Path(corpus)
    errs = validate_bundle(bundle)
    report_errs = [e for e in errs if not e.startswith("hypotheses.json")]
    if report_errs:
        raise CorpusError("bundle is invalid:\n" + "\n".join(report_errs))
    report = json.loads((bundle / "report.json").read_text(encoding="utf-8"))
    if not report["provenance"].get("pinned"):
        raise CorpusError("only bundles pinned to a clean commit can enter the corpus")
    repo = repo_id(report, bundle.resolve().name)
    dest = corpus / "bundles" / repo.replace("/", "__")
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for f in BUNDLE_FILES:
        if (bundle / f).exists() and not (f == "hypotheses.json" and errs):
            shutil.copy2(bundle / f, dest / f)
    (dest / "metrics").mkdir(exist_ok=True)
    if (bundle / "metrics" / "complexity.json").exists():
        shutil.copy2(bundle / "metrics" / "complexity.json", dest / "metrics" / "complexity.json")
    entry = {"repo": repo, "commit_sha": report["provenance"]["commit_sha"],
             "evidence_digest": report["evidence_digest"], "tool_version": report["tool"]["version"],
             "inference": not errs and (bundle / "hypotheses.json").exists(),
             "inference_rejected": len(errs) if errs else 0,
             "added_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
             "path": str(dest.relative_to(corpus))}
    index = load_index(corpus)
    index["repos"] = [r for r in index["repos"] if r["repo"] != repo] + [entry]
    index["repos"].sort(key=lambda r: r["repo"])
    (corpus / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    build(corpus)
    return entry


def load_index(corpus: Path) -> dict:
    p = Path(corpus) / "index.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {"schema_version": "0.2.0", "repos": []}


def load_bundles(corpus: Path) -> list[dict]:
    out = []
    for r in load_index(corpus)["repos"]:
        d = Path(corpus) / r["path"]
        rep = json.loads((d / "report.json").read_text(encoding="utf-8"))
        hyp = json.loads((d / "hypotheses.json").read_text(encoding="utf-8")) if (d / "hypotheses.json").exists() else None
        ev = {json.loads(x)["id"]: json.loads(x) for x in (d / "evidence.jsonl").read_text(encoding="utf-8").splitlines() if x}
        out.append({"repo": r["repo"], "ref": _ref(r["repo"], rep["provenance"]["commit_sha"]),
                    "report": rep, "hyp": hyp, "evidence": ev})
    return out


# ------------------------------------------------------------------ facts
def facts_for(b: dict) -> list[dict]:
    rep, hyp, ref = b["report"], b["hyp"], b["ref"]
    subj = f"repo:{b['repo']}"
    g = lambda ids: [f"{ref}#{i}" for i in ids or [] if i]  # noqa: E731
    F: list[dict] = []

    def fact(s, p, o, status, ev, conf=None, **q):
        F.append({"subject": s, "predicate": p, "object": o, "status": status,
                  "confidence": conf if conf is not None else (1.0 if status == "CONFIRMED" else None),
                  "evidence": ev, "qualifiers": q, "source": ref})

    for label in rep["repo_shape"]["hypothesis"]:
        fact(subj, "has_shape", f"shape:{label}", "INFERRED", g([rep["repo_shape"]["evidence_id"]]), 0.6)
    for e in rep["entrypoints"]:
        fact(subj, "has_entrypoint", f"entry:{e['type']}", e["status"], g([e["evidence_id"]]), module=e.get("module"))
    total = sum(c["code_lines"] for c in rep["components"]["items"]) or 1
    for c in rep["components"]["items"]:
        cid = f"component:{b['repo']}::{c['name']}"
        fact(subj, "has_component", cid, "CONFIRMED", g([c["evidence_id"]]), code_lines=c["code_lines"],
             share=round(c["code_lines"] / total, 4), synthetic=c.get("synthetic", False))
        for sig in c["signals"]:
            fact(cid, "implements_with", f"signature:{sig}", "CONFIRMED", g([c["evidence_id"]]))
    for s in rep["signals"]:
        comps = sorted(c["name"] for c in rep["components"]["items"] if s["signature"] in c["signals"])
        q = dict(usage_level=s["usage_level"], signature=s["signature"], library=s["library"],
                 category=s["category"], subcategory=s["subcategory"], components=comps,
                 reachable=s["reachable_from_entrypoint"])
        fact(subj, "uses_primitive", f"primitive:{s['primitive']}", "CONFIRMED", g([s["evidence_id"]]), **q)
        for sub in s.get("refined_primitives") or {}:
            fact(subj, "uses_primitive", f"primitive:{sub}", "CONFIRMED", g([s["evidence_id"]]),
                 **{**q, "refined_from": s["primitive"]})
    if hyp:
        for c in hyp.get("components", []):
            cid = f"component:{b['repo']}::{c['name']}"
            for r in c.get("roles", []):
                fact(cid, "has_role", f"role:{r}", c["status"], g(c.get("evidence_ids")), c.get("confidence"),
                     responsibility=c["responsibility"])
        for h in hyp.get("architecture_hypotheses", []):
            fact(subj, "exhibits_pattern", f"pattern:{h['pattern_id']}", h["status"], g(h.get("evidence_ids")),
                 h.get("confidence"), claim=h["claim"], counter=g(h.get("counter_evidence_ids")),
                 counter_notes=h.get("counter_evidence_notes", []))
        for r in hyp.get("primitive_roles", []):
            sig = next((s for s in rep["signals"] if s["signature"] == r["signature"]), None)
            if sig:
                fact(subj, "primitive_role", f"primitive:{sig['primitive']}", "INFERRED", g(r.get("evidence_ids")),
                     None, role=r["role"], signature=r["signature"], rationale=r.get("rationale"))
        a = hyp.get("ai_assessment")
        if a:
            fact(subj, "ai_classification", f"ai:{a['classification']}", "INFERRED", g(a.get("evidence_ids")), None,
                 deterministic_core=a.get("deterministic_core", []))
    return F


def build(corpus: Path) -> list[dict]:
    facts = [f for b in load_bundles(corpus) for f in facts_for(b)]
    with (Path(corpus) / "facts.jsonl").open("w", encoding="utf-8") as fh:
        for f in facts:
            fh.write(json.dumps(f, ensure_ascii=False, sort_keys=True) + "\n")
    return facts


# ------------------------------------------------------------------ comparisons
def compare(corpus: Path) -> dict:
    bundles = load_bundles(corpus)
    facts = build(corpus)
    repos = [b["repo"] for b in bundles]
    by_pred = defaultdict(list)
    for f in facts:
        by_pred[f["predicate"]].append(f)

    # A. primitive matrix
    matrix: dict[str, dict] = {}
    for f in by_pred["uses_primitive"]:
        q = f["qualifiers"]
        if q["category"] not in COMPARED_CATEGORIES or q.get("refined_from"):
            continue
        prim = f["object"].split(":", 1)[1]
        row = matrix.setdefault(prim, {"primitive": prim, "category": q["category"], "cells": {}})
        repo = f["subject"].split(":", 1)[1]
        cell = row["cells"].setdefault(repo, {"usage_level": q["usage_level"], "libraries": [], "library_levels": {},
                                              "evidence": [], "role": None, "role_status": None})
        if LEVEL_RANK[q["usage_level"]] > LEVEL_RANK[cell["usage_level"]]:
            cell["usage_level"] = q["usage_level"]
        prev = cell["library_levels"].get(q["library"])
        if prev is None or LEVEL_RANK[q["usage_level"]] > LEVEL_RANK[prev]:
            cell["library_levels"][q["library"]] = q["usage_level"]
        # libraries actually used by production code; declared-only ones stay in library_levels
        cell["libraries"] = sorted(lib for lib, lv in cell["library_levels"].items()
                                   if LEVEL_RANK[lv] >= LEVEL_RANK["IMPORTED"]) or sorted(cell["library_levels"])
        cell["evidence"] += f["evidence"]
        cell["refined"] = sorted({x["object"].split(":", 1)[1] for x in by_pred["uses_primitive"]
                                  if x["subject"] == f["subject"] and x["qualifiers"].get("refined_from") == prim})
    for f in by_pred["primitive_role"]:
        prim = f["object"].split(":", 1)[1]
        repo = f["subject"].split(":", 1)[1]
        if prim in matrix and repo in matrix[prim]["cells"]:
            matrix[prim]["cells"][repo].update(role=f["qualifiers"]["role"], role_status="INFERRED")
    rows = []
    for prim, row in matrix.items():
        used = [r for r, c in row["cells"].items() if LEVEL_RANK[c["usage_level"]] >= LEVEL_RANK["IMPORTED"]]
        row["used_by"] = len(used)
        row["shared"] = len(used) >= 2
        row["libraries_across_repos"] = sorted({lib for r_, c in row["cells"].items() if r_ in used for lib in c["libraries"]})
        row["claim"] = (f"{len(used)} of {len(repos)} repositories import or call {prim}"
                        + (f" via {len(row['libraries_across_repos'])} different libraries"
                           if len(row["libraries_across_repos"]) > 1 else ""))
        row["status"] = "CONFIRMED"
        rows.append(row)
    rows.sort(key=lambda r: (-r["used_by"], r["category"], r["primitive"]))

    # B. similarity on primitive sets (production use only)
    sets = {r: {row["primitive"] for row in rows if r in row["cells"]
                and LEVEL_RANK[row["cells"][r]["usage_level"]] >= LEVEL_RANK["IMPORTED"]} for r in repos}
    sim = []
    for a, b in combinations(repos, 2):
        inter, union = sets[a] & sets[b], sets[a] | sets[b]
        sim.append({"a": a, "b": b, "jaccard": round(len(inter) / len(union), 3) if union else None,
                    "shared": sorted(inter), "only_a": sorted(sets[a] - sets[b]), "only_b": sorted(sets[b] - sets[a]),
                    "status": "CONFIRMED"})

    # C. roles: same role, different implementation
    comp_sigs = defaultdict(set)
    for f in by_pred["implements_with"]:
        comp_sigs[f["subject"]].add(f["object"].split(":", 1)[1])
    sig_info = {}
    for f in by_pred["uses_primitive"]:
        q = f["qualifiers"]
        if not q.get("refined_from"):
            sig_info[(f["subject"].split(":", 1)[1], q["signature"])] = (q["library"], f["object"].split(":", 1)[1],
                                                                      q["subcategory"])
    role_vocab = load_config().roles
    roles: dict[str, dict] = {}
    for f in by_pred["has_role"]:
        role = f["object"].split(":", 1)[1]
        comp = f["subject"]
        repo, cname = comp.split(":", 1)[1].split("::", 1)
        allowed = set((role_vocab.get(role) or {}).get("implemented_by") or [])
        impls = sorted({sig_info[(repo, s)][:2] for s in comp_sigs.get(comp, set())
                        if (repo, s) in sig_info and sig_info[(repo, s)][2] in allowed}, key=lambda t: t[0])
        entry = roles.setdefault(role, {"role": role, "repos": {}})
        r = entry["repos"].setdefault(repo, {"components": [], "implementations": set(), "statuses": [], "evidence": []})
        r["components"].append({"name": cname, "responsibility": f["qualifiers"]["responsibility"],
                                "confidence": f["confidence"]})
        r["implementations"] |= {f"{lib} ({prim})" for lib, prim in impls}
        r["statuses"].append(f["status"])
        r["evidence"] += f["evidence"]
    role_rows = []
    for role, entry in roles.items():
        impl_sets = {repo: frozenset(r["implementations"]) for repo, r in entry["repos"].items()}
        for r in entry["repos"].values():
            r["implementations"] = sorted(r["implementations"])
            r["status"] = weakest(*r["statuses"])
            del r["statuses"]
        n = len(entry["repos"])
        entry["in_repos"] = n
        entry["differs"] = n >= 2 and len(set(impl_sets.values())) > 1
        entry["status"] = weakest(*(r["status"] for r in entry["repos"].values()))
        entry["definition"] = (role_vocab.get(role) or {}).get("definition", "")
        entry["claim"] = (f"{n} repositories have a {role} component" +
                          ("; their implementations differ" if entry["differs"] else ""))
        role_rows.append(entry)
    role_rows.sort(key=lambda r: (-r["in_repos"], r["role"]))

    # D. patterns
    pats: dict[str, dict] = {}
    for f in by_pred["exhibits_pattern"]:
        p = f["object"].split(":", 1)[1]
        e = pats.setdefault(p, {"pattern": p, "repos": {}})
        e["repos"][f["subject"].split(":", 1)[1]] = {"confidence": f["confidence"], "status": f["status"],
                                                     "claim": f["qualifiers"]["claim"], "evidence": f["evidence"],
                                                     "counter_notes": f["qualifiers"]["counter_notes"]}
    pat_vocab = load_config().patterns
    pattern_rows = []
    families: dict[str, dict] = {}
    for e in pats.values():
        e["in_repos"] = len(e["repos"])
        e["status"] = weakest(*(r["status"] for r in e["repos"].values()))
        e["definition"] = (pat_vocab.get(e["pattern"]) or {}).get("definition", "")
        e["family"] = (pat_vocab.get(e["pattern"]) or {}).get("parent") or e["pattern"]
        pattern_rows.append(e)
        fam = families.setdefault(e["family"], {"family": e["family"], "members": set(), "repos": {}})
        fam["members"].add(e["pattern"])
        for repo, x in e["repos"].items():
            prev = fam["repos"].get(repo)
            if prev is None or (x["confidence"] or 0) > (prev["confidence"] or 0):
                fam["repos"][repo] = {"pattern": e["pattern"], "confidence": x["confidence"], "status": x["status"]}
    pattern_rows.sort(key=lambda r: (-r["in_repos"], r["pattern"]))
    family_rows = []
    for fam in families.values():
        fam["members"] = sorted(fam["members"])
        fam["in_repos"] = len(fam["repos"])
        fam["status"] = weakest(*(r["status"] for r in fam["repos"].values()))
        if fam["in_repos"] >= 2 and len(fam["members"]) > 1:
            family_rows.append(fam)
    family_rows.sort(key=lambda r: -r["in_repos"])

    # E. per-repo profile (size-normalized where it matters)
    profiles = []
    for b in bundles:
        rep, hyp = b["report"], b["hyp"] or {}
        cx = rep["complexity"].get("cyclomatic", {})
        profiles.append({
            "repo": b["repo"], "ref": b["ref"], "shape": rep["repo_shape"]["hypothesis"],
            "ai": (hyp.get("ai_assessment") or {}).get("classification", "not assessed"),
            "deterministic_core": (hyp.get("ai_assessment") or {}).get("deterministic_core", []),
            "production_modules": rep["module_graph"]["production_modules"],
            "code_lines": rep["tests"]["production_code_lines"], "components": len(rep["components"]["items"]),
            "test_ratio": rep["tests"]["test_to_production_ratio"], "cc_p95": cx.get("p95"),
            "import_time_cycles": len(rep["module_graph"]["import_time_cycles"]),
            "entry_types": sorted({e["type"] for e in rep["entrypoints"]}),
            "inference": b["hyp"] is not None, "unknowns": len(rep["unknowns"]) + len(hyp.get("unknowns", [])),
        })

    result = {"schema_version": "0.2.0", "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
              "repos": profiles, "primitives": rows, "similarity": sim, "roles": role_rows,
              "patterns": pattern_rows, "pattern_families": family_rows, "facts": len(facts),
              "rule": "A cross-repository statement takes the weakest status of its inputs."}
    (Path(corpus) / "compare.json").write_text(json.dumps(result, indent=2, ensure_ascii=False, default=list) + "\n",
                                               encoding="utf-8")
    lookup = {}
    for b in bundles:
        for eid, item in b["evidence"].items():
            lookup[f"{b['ref']}#{eid}"] = {"item": item, "repo": b["repo"], "sha": b["report"]["provenance"]["commit_sha"]}
    from .corpus_html import render_compare
    render_compare(result, Path(corpus) / "compare.html", lookup)
    return result
