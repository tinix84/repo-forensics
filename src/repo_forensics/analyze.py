"""Pipeline: ACQUIRE -> FINGERPRINT -> MEASURE -> DECOMPOSE -> (INFER: left to the LLM) -> REPORT.

Each phase is a method of `Analyzer`; phases communicate only through attributes set on
the instance, so every phase can be read (and tested) on its own.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath

from . import SCHEMA_VERSION, __version__
from . import acquire as acq_mod
from . import components as comp_mod
from .config import Config, Signature, load_config, normalize_dist
from .dependencies import collect as collect_deps
from .dependencies import import_to_dist
from .evidence import EvidenceStore, loc
from .fingerprint import fingerprint
from .graphmetrics import cycles, distribution, fan, percentile, reachable
from .pymodules import build_graph, module_name, python_roots
from .pyparse import FileFacts, parse_file

BUILD_SCRIPTS = {"setup.py", "noxfile.py", "fabfile.py", "tasks.py", "conftest.py"}
CONFIG_ENV_PATTERN = re.compile(r"MODEL|PROVIDER|BACKEND|ENGINE|URL|HOST|ENDPOINT|DATABASE|DB_|STORE|INDEX|REGION")
USAGE_ORDER = ["CALLED", "IMPORTED", "DECLARED", "NON_PRODUCTION_ONLY"]
TEST_FRAMEWORKS = ("pytest", "unittest", "hypothesis", "nose", "doctest")


def _prefix_match(name: str, prefix: str) -> bool:
    return name == prefix or name.startswith(prefix + ".")


def run(target: str, out_dir: Path, ref: str | None = None, tier: int = 1,
        workdir: Path | None = None, keep_clone: bool = False,
        component_depth: int | None = None, extra_signatures: str | None = None) -> dict:
    """Acquire `target`, analyze it, write the artifact bundle to `out_dir`, return the report."""
    cfg = load_config(extra_signatures)
    tmp_created = None
    if acq_mod.is_remote(target):
        base = workdir or Path(tempfile.mkdtemp(prefix="repo-forensics-"))
        tmp_created = None if workdir else base
        acq = acq_mod.clone(target, base / "repo", ref)
    else:
        if ref:
            raise acq_mod.AcquireError("--ref is only supported for remote targets; check out the ref locally instead")
        acq = acq_mod.open_local(Path(target))
    try:
        an = Analyzer(cfg, acq, tier, component_depth, raw_dir=Path(out_dir) / "raw")
        report = an.run()
    finally:
        if tmp_created and not keep_clone:
            shutil.rmtree(tmp_created, ignore_errors=True)
    if keep_clone and acq.cloned:
        report["provenance"]["clone_path"] = str(acq.root)
    from .render import write_outputs
    write_outputs(report, an.ev.as_dicts(), out_dir)
    return report


class Analyzer:
    def __init__(self, cfg: Config, acq: acq_mod.Acquired, tier: int = 1, component_depth: int | None = None,
                 raw_dir: Path | None = None):
        self.cfg, self.acq, self.tier, self.component_depth = cfg, acq, tier, component_depth
        self.raw_dir = raw_dir
        self.tool_runs: dict = {}
        self.dyn: dict | None = None
        self.fusion: dict = {}
        self.th = cfg.thresholds
        self.ev = EvidenceStore(self.th.get("max_locations_per_evidence", 15))
        self.unknowns: list[dict] = []
        self.smells: list[dict] = []
        self.notes: list[str] = []

    # ------------------------------------------------------------------ helpers
    def unknown(self, phase: str, question: str, reason: str, locations: list[dict] | None = None,
                data: dict | None = None) -> str:
        eid = self.ev.add(phase, "unknown", question, "UNKNOWN", evidence=locations,
                          data={"reason": reason, **(data or {})})
        self.unknowns.append({"question": question, "reason": reason, "evidence_id": eid})
        return eid

    def smell(self, rule: str, target: str, detail: str, eid: str, severity: str = "warn") -> None:
        self.smells.append({"rule": rule, "target": target, "detail": detail, "severity": severity,
                            "evidence_id": eid})

    def run(self) -> dict:
        self.files = acq_mod.list_files(self.acq)
        self.phase_provenance()
        self.phase_fingerprint()
        self.phase_parse_python()
        self.phase_graph()
        self.phase_dependencies()
        self.phase_entrypoints()
        self.phase_signals()
        self.phase_config_and_ai()
        self.phase_decompose()
        self.phase_complexity()
        self.phase_tests()
        self.phase_toolchain()
        self.phase_dynamic()
        self.phase_fusion()
        return self.assemble()

    # ---------------------------------------------------- tier 1: external static analyzers
    def phase_toolchain(self) -> None:
        if self.tier < 1:
            return
        from .adapters import static_tools
        paths = sorted(self.path_of[m] for m in self.prod)
        if not paths:
            return
        root = self.acq.root
        for name, fn in (("ruff", static_tools.ruff), ("vulture", static_tools.vulture), ("bandit", static_tools.bandit)):
            tr = fn(root, paths)
            self.tool_runs[name] = tr
            if tr.status != "ok":
                self.notes.append(f"{name}: {tr.status} ({tr.note or ''})".strip())
        rt = self.tool_runs.get("ruff")
        if rt and rt.status == "ok":
            by_rule = defaultdict(list)
            for f in rt.findings:
                by_rule[f.rule].append(f)
            for rule, fs in sorted(by_rule.items(), key=lambda kv: -len(kv[1])):
                self.ev.add("toolchain", "tool.ruff", f"ruff reports {rule} at {len(fs)} location(s)", "CONFIRMED",
                            evidence=[loc(file=f.file, line=f.line, detail=f.message[:120]) for f in fs], tool="ruff",
                            source="tool-output", data={"rule": rule, "count": len(fs), "example": fs[0].message[:200]})
        vt = self.tool_runs.get("vulture")
        if vt and vt.status == "ok":
            kinds = Counter(f.kind for f in vt.findings)
            self.ev.add("toolchain", "tool.vulture", f"vulture reports {len(vt.findings)} possibly unused names "
                        f"({', '.join(f'{n} {k}' for k, n in kinds.most_common())})", "CONFIRMED", tool="vulture",
                        source="tool-output", data={"by_kind": dict(kinds)},
                        counter=[loc(detail="name-usage heuristic; 60-100% confidence per finding; see fusion verdicts")])

    # ---------------------------------------------------- tier 2: dynamic run (executes the target's code)
    def phase_dynamic(self) -> None:
        if self.tier < 2:
            return
        from .dynamic.sandbox import run_tier2
        self.dyn = run_tier2(self, self.raw_dir)
        d = self.dyn
        self.ev.add("dynamic", "dynamic.run", f"Tier 2 run {d['status']}: dependencies installed as wheels only "
                    f"({len(d['install']['failed'])} failed), {len(d['entry_probes'])} entry probes, tests "
                    f"{'run' if d['tests'].get('ran') else 'not run'}", "CONFIRMED" if d["status"] != "failed" else "UNKNOWN",
                    source="dynamic", tool="repo-forensics/sandbox",
                    data={"isolation": d["isolation"], "python": d["python"], "elapsed_s": d["elapsed_s"],
                          "install_failed": d["install"]["failed"]},
                    counter=[loc(detail="observations hold for this run only; absence of execution is not proof of absence")])
        if d["install"]["failed"]:
            self.unknown("dynamic", "Which behaviour depends on dependencies that could not be installed as wheels?",
                         f"{len(d['install']['failed'])} requirements have no compatible wheel: "
                         f"{', '.join(d['install']['failed'][:8])}")

    def phase_fusion(self) -> None:
        if self.tier < 1:
            return
        from .fusion import Fusion
        self.fusion = Fusion(self, self.tool_runs, self.dyn).run()

    # ================================================================ ACQUIRE
    def phase_provenance(self) -> None:
        acq, ev = self.acq, self.ev
        if acq.commit_sha and not acq.dirty:
            ev.add("acquire", "provenance.commit", f"Analysis is pinned to commit {acq.commit_sha}", "CONFIRMED",
                   evidence=[loc(detail=f"git rev-parse HEAD = {acq.commit_sha}")], tool="git")
        elif acq.commit_sha:
            ev.add("acquire", "provenance.commit", f"Working tree at {acq.commit_sha} has uncommitted changes; "
                   "results are not reproducible from the SHA alone", "SUPPORTED",
                   evidence=[loc(detail="git status --porcelain is non-empty")], tool="git")
        else:
            self.unknown("acquire", "Which commit does this analysis correspond to?",
                         "Target is not a git repository; results cannot be pinned to a commit.")
        self.spdx, self.lic_file = acq_mod.detect_license(acq.root, self.files)
        if self.spdx and self.spdx != "UNRECOGNIZED":
            ev.add("acquire", "provenance.license", f"License text matches {self.spdx}", "SUPPORTED",
                   evidence=[loc(file=self.lic_file, detail="heuristic text match on license file")])
        elif self.spdx == "UNRECOGNIZED":
            self.unknown("acquire", "Under which license is the repository distributed?",
                         "A license file exists but its text matched no known template.", [loc(file=self.lic_file)])
        else:
            self.unknown("acquire", "Under which license is the repository distributed?",
                         "No top-level LICENSE/COPYING file.")

    # ========================================================== FINGERPRINT
    def phase_fingerprint(self) -> None:
        fp = self.fp = fingerprint(self.acq.root, self.files, self.cfg.ignore)
        ev = self.ev
        self.analysis_coverage = {}
        for lang, st in fp.languages.items():
            if st["kind"] != "programming" or not st["source_code_lines"]:
                continue
            ev.add("fingerprint", "language", f"{lang} accounts for {st['source_share']:.1%} of production "
                   f"code lines ({st['source_code_lines']} lines in {st['files']} files)", "CONFIRMED",
                   data={"language": lang, **{k: st[k] for k in ("files", "source_code_lines", "source_share")}},
                   tool="repo-forensics/fingerprint")
            self.analysis_coverage[lang] = "deep" if lang == "Python" else "fingerprint-only"
            if lang != "Python" and (st["source_share"] or 0) >= 0.05:
                self.unknown("fingerprint", f"What is the internal structure of the {lang} code?",
                             f"{lang} is {st['source_share']:.0%} of production code; v0.1 analyzes Python only.",
                             data={"language": lang, "source_code_lines": st["source_code_lines"]})
        for m in fp.manifests:
            ev.add("fingerprint", "manifest", f"Build/package manifest {m['path']} ({m['build_system']})",
                   "CONFIRMED", evidence=[loc(file=m["path"])], data=m)
        if fp.multi_package:
            ev.add("fingerprint", "repo.multi_package",
                   f"Repository contains {len(fp.package_roots)} package roots (monorepo-like layout)", "CONFIRMED",
                   evidence=[loc(file=r["dir"], detail=", ".join(r["manifests"])) for r in fp.package_roots])
        nb = [f.path for f in fp.files if f.language == "Jupyter Notebook"]
        if nb:
            self.unknown("fingerprint", "What logic lives in Jupyter notebooks?",
                         f"{len(nb)} notebooks present; notebooks are not parsed in v0.1.", [loc(file=p) for p in nb])

    # ============================================================== MEASURE
    def phase_parse_python(self) -> None:
        fp, root = self.fp, self.acq.root
        py_infos = [f for f in fp.files if f.path.endswith(".py")
                    and f.file_class not in ("vendored", "generated", "migrations")]
        all_dirs = {"/".join(PurePosixPath(f).parts[:i]) for f in self.files
                    for i in range(1, len(PurePosixPath(f).parts))}
        self.roots = python_roots([f.path for f in py_infos], [m["path"] for m in fp.manifests], all_dirs)
        self.facts: list[FileFacts] = []
        seen: dict[str, str] = {}
        collisions, large = [], []
        max_bytes = self.cfg.ignore.get("max_parse_bytes", 2_000_000)
        for fi in py_infos:
            mod, is_pkg = module_name(fi.path, self.roots)
            if not mod:
                continue
            if mod in seen:
                if "source" in (fi.file_class, fp.by_path[seen[mod]].file_class):
                    collisions.append((mod, seen[mod], fi.path))
            elif fi.size > max_bytes:
                large.append(fi.path)
            else:
                seen[mod] = fi.path
                self.facts.append(parse_file(fi.path, (root / fi.path).read_bytes(), mod, is_pkg))
        bad = [f for f in self.facts if f.syntax_error]
        if bad:
            self.unknown("measure", "What do the files that failed to parse contain?",
                         f"{len(bad)} Python files could not be parsed (e.g. Python 2 syntax or templates).",
                         [loc(file=f.path, detail=f.syntax_error) for f in bad])
        if collisions:
            self.unknown("measure", "Which of several files with the same module name is imported at runtime?",
                         f"{len(collisions)} module-name collisions across import roots.",
                         [loc(file=b, detail=f"{m} also defined by {a}") for m, a, b in collisions])
        if large:
            self.unknown("measure", "What do very large Python files contain?",
                         f"{len(large)} files exceed the parse size limit.", [loc(file=p) for p in large])
        self.fact_of = {f.module: f for f in self.facts}
        self.path_of = {f.module: f.path for f in self.facts}
        self.cls_of = {f.module: fp.by_path[f.path].file_class for f in self.facts}
        self.loc_of = {f.module: fp.by_path[f.path].code for f in self.facts}
        self.prod = {m for m, c in self.cls_of.items()
                     if c == "source" and PurePosixPath(self.path_of[m]).name not in BUILD_SCRIPTS
                     and not self.fact_of[m].syntax_error}
        self.tests = {m for m, c in self.cls_of.items() if c == "test"}
        self.internal_tops = {m.split(".")[0] for m in self.fact_of}

    def phase_graph(self) -> None:
        g = self.graph = build_graph([f for f in self.facts if not f.syntax_error])
        prod = self.prod
        self.full_adj = g.adjacency(("module", "lazy"))
        self.prod_adj = {m: {d for d in self.full_adj.get(m, ()) if d in prod} for m in prod}
        it_full = g.adjacency(("module",))
        self.import_time_adj = {m: {d for d in it_full.get(m, ()) if d in prod} for m in prod}
        self.fan_in, self.fan_out = fan(self.prod_adj)
        self.ev.add("measure", "graph.size", f"Internal Python import graph: {len(prod)} production modules, "
                    f"{sum(len(v) for v in self.prod_adj.values())} distinct module-to-module import edges",
                    "CONFIRMED", tool="repo-forensics/ast",
                    data={"production_modules": len(prod), "test_modules": len(self.tests),
                          "edges_total_all_kinds": len(g.edges), "import_roots": [r or "." for r in self.roots]})
        unresolved = g.unresolved_internal + g.unresolved_relative
        if unresolved:
            self.unknown("measure", "Where do some internal-looking imports resolve to?",
                         f"{len(unresolved)} imports reference internal names that match no parsed module "
                         "(generated code, namespace tricks, or optional modules).",
                         [loc(file=self.path_of.get(s), line=ln, symbol=t) for s, t, ln in unresolved])
        self._cycles()
        self._module_hotspots()

    def _cycles(self) -> None:
        self.rt_cycles = cycles(self.prod_adj)
        self.it_cycles = cycles(self.import_time_adj)
        for c in self.rt_cycles:
            members = set(c)
            sites = [loc(file=self.path_of[e.src], line=e.line, symbol=f"{e.src} -> {e.dst}", detail=e.kind)
                     for e in self.graph.edges if e.src in members and e.dst in members and e.kind != "type_checking"]
            import_time = any(set(x) <= members for x in self.it_cycles)
            eid = self.ev.add("measure", "graph.cycle",
                              f"Import cycle among {len(c)} modules: {', '.join(c[:6])}{'…' if len(c) > 6 else ''}",
                              "CONFIRMED", evidence=sites, data={"members": c, "import_time": import_time},
                              tool="repo-forensics/tarjan")
            how = "at import time" if import_time else "only via function-level imports"
            self.smell("cyclic_dependency", ", ".join(c[:4]) + ("…" if len(c) > 4 else ""),
                       f"{len(c)}-module cycle ({how})", eid, "warn" if import_time else "info")

    def _module_hotspots(self) -> None:
        prod, fi, fo, lc, th = self.prod, self.fan_in, self.fan_out, self.loc_of, self.th
        self.fi_vals = [fi[m] for m in prod]
        self.fo_vals = [fo[m] for m in prod]
        self.loc_vals = [lc[m] for m in prod]
        gm, om, hm = th["god_module"], th["oversized_module"], th["hub_module"]
        p_fi = percentile(self.fi_vals, gm["percentile"]) or 0
        p_fo = percentile(self.fo_vals, gm["percentile"]) or 0
        p_loc = percentile(self.loc_vals, gm["percentile"]) or 0
        for m in sorted(prod):
            if (fi[m] > p_fi and fo[m] > p_fo and lc[m] > p_loc and fi[m] >= gm["min_fan_in"]
                    and fo[m] >= gm["min_fan_out"] and lc[m] >= gm["min_loc"]):
                eid = self.ev.add("measure", "module.god_candidate",
                                  f"{m} is above P{gm['percentile']} in fan-in ({fi[m]}), fan-out ({fo[m]}) "
                                  f"and size ({lc[m]} LOC)", "CONFIRMED", evidence=[loc(file=self.path_of[m])],
                                  data={"fan_in": fi[m], "fan_out": fo[m], "loc": lc[m]})
                self.smell("god_module", m, f"fan-in {fi[m]}, fan-out {fo[m]}, {lc[m]} LOC", eid)
        limit = max(percentile(self.loc_vals, om["percentile"]) or 0, om["min_loc"])
        for m in sorted(prod):
            if lc[m] > limit:
                eid = self.ev.add("measure", "module.oversized", f"{m} has {lc[m]} code lines", "CONFIRMED",
                                  evidence=[loc(file=self.path_of[m])], data={"loc": lc[m]})
                self.smell("oversized_module", m, f"{lc[m]} code lines", eid, "info")
        p_hub = percentile(self.fi_vals, hm["percentile"]) or 0
        self.hubs = sorted((m for m in prod if fi[m] > p_hub and fi[m] >= hm["min_fan_in"]),
                           key=lambda m: -fi[m])[: th["max_hotspots"]]
        for m in self.hubs:
            importers = sorted(s for s, ds in self.prod_adj.items() if m in ds)
            self.ev.add("measure", "module.hub", f"{m} is imported by {fi[m]} production modules", "CONFIRMED",
                        evidence=[loc(file=self.path_of[s], symbol=f"{s} -> {m}") for s in importers],
                        data={"fan_in": fi[m]})

    # ---------------------------------------------------- dependencies
    def _candidate_dists(self, full: str) -> set[str]:
        top = full.split(".")[0]
        n = normalize_dist(top)
        c = {import_to_dist(full, self.cfg.import_aliases), n, f"python-{n}", f"py{n}", f"{n}-python", f"{n}-py"}
        for s in self.cfg.signatures:
            if any(p.split(".")[0] == top for p in s.modules):
                c |= set(s.distributions)
        return c

    def phase_dependencies(self) -> None:
        declared, self.metas, errors = collect_deps(self.acq.root, self.fp.manifests)
        for d in declared:  # manifests under tests/, examples/, docs/ never describe the product's runtime
            fi = self.fp.by_path.get(d.manifest)
            if fi and fi.file_class in ("test", "auxiliary", "docs", "vendored"):
                d.scope = "non-production"
        self.metas = [m for m in self.metas if self.fp.by_path.get(m["manifest"]) is None
                      or self.fp.by_path[m["manifest"]].file_class not in ("test", "auxiliary", "docs", "vendored")]
        self.declared = declared
        for e in errors:
            self.unknown("measure", f"What does {e['manifest']} declare?", f"Manifest failed to parse: {e['error']}",
                         [loc(file=e["manifest"])])
        for meta in self.metas:
            if meta.get("non_literal"):
                self.unknown("measure", f"Which dependencies/entry points does {meta['manifest']} compute dynamically?",
                             f"setup() arguments {meta['non_literal']} are not literals; setup.py is never executed.",
                             [loc(file=meta["manifest"])])
        self.declared_set = {d.name for d in declared if d.scope != "non-production"}
        self.declared_by_scope: dict[str, set[str]] = defaultdict(set)
        for d in declared:
            self.declared_by_scope[d.scope.split(":")[0]].add(d.name)
        self.third_party, self.undeclared = [], []
        imported_dists: set[str] = set()
        for top, sites in sorted(self.graph.third_party.items()):
            imported_dists |= self._record_third_party(top, sites)
        if self.undeclared:
            eid = self.ev.add("measure", "dependency.imported_not_declared",
                              f"{len(self.undeclared)} third-party packages are imported at runtime by production code "
                              "but not declared in any production manifest", "CONFIRMED",
                              data={"packages": [t for t, _ in self.undeclared],
                                    "evidence_ids": [e for _, e in self.undeclared]},
                              counter=[loc(detail="usually satisfied transitively (e.g. pydantic via fastapi) or via "
                                           "an import-name alias missing from import_aliases.yaml")])
            self.smell("undeclared_import", ", ".join(t for t, _ in self.undeclared[:6])
                       + ("…" if len(self.undeclared) > 6 else ""),
                       f"{len(self.undeclared)} packages imported but not declared (relying on transitive deps?)", eid, "info")
        self.undeclared = [t for t, _ in self.undeclared]
        if self.declared_set:
            self._dependency_mismatches(imported_dists)
        elif self.graph.third_party:
            self.unknown("measure", "Which third-party dependencies are formally declared?",
                         "No parseable Python dependency manifest was found.")

    def _record_third_party(self, top: str, sites: list) -> set[str]:
        fulls = sorted({s[2] for s in sites})
        cands = set().union(*(self._candidate_dists(f) for f in fulls))
        matched = sorted(cands & self.declared_set)
        prod_sites = [s for s in sites if s[0] in self.prod]
        runtime_prod = [s for s in prod_sites if s[3] != "type_checking"]
        entry = {"import_name": top, "distribution_guess": import_to_dist(fulls[0], self.cfg.import_aliases),
                 "declared_as": matched, "modules_importing": len({s[0] for s in sites}),
                 "production_modules_importing": len({s[0] for s in prod_sites}),
                 "type_checking_only": bool(prod_sites) and not runtime_prod,
                 "sites_by_class": dict(Counter(self.cls_of.get(s[0], "other") for s in sites))}
        self.third_party.append(entry)
        if prod_sites:
            eid = self.ev.add("measure", "dependency.imported",
                              f"Production code imports third-party package `{top}` in "
                              f"{entry['production_modules_importing']} modules", "CONFIRMED",
                              evidence=[loc(file=self.path_of[s[0]], line=s[1], symbol=s[2]) for s in prod_sites],
                              data=entry)
            if self.declared_set and not matched and runtime_prod:
                self.undeclared.append((top, eid))
        return cands

    def _dependency_mismatches(self, imported_dists: set[str]) -> None:
        unused = sorted(d for d in self.declared_by_scope.get("runtime", set())
                        if d not in imported_dists and d not in self.cfg.non_import_tools
                        and not d.startswith("types-"))
        self.unused = unused
        for d in unused:
            src = next(x for x in self.declared if x.name == d)
            eid = self.ev.add("measure", "dependency.declared_not_imported",
                              f"Runtime dependency `{d}` is declared but no Python import of it was found",
                              "CONFIRMED", evidence=[loc(file=src.manifest, line=src.line, symbol=src.raw)],
                              counter=[loc(detail="could be a plugin, server, CLI tool or loaded dynamically")])
            self.smell("possibly_unused_dependency", d, "declared in runtime scope, never imported", eid, "info")

    # ---------------------------------------------------- entry points
    def _add_entry(self, module: str | None, etype: str, status: str, how: str, location: dict,
                   name: str | None = None, spec: str | None = None) -> None:
        if any(e["module"] == module and e["type"] == etype and e.get("name") == name for e in self.entries):
            return
        eid = self.ev.add("measure", "entrypoint", f"{etype} entry point{f' `{name}`' if name else ''} "
                          f"at {module or location.get('file')} ({how})", status, evidence=[location],
                          data={"type": etype, "module": module, "detection": how})
        self.entries.append({"name": name, "type": etype, "module": module, "spec": spec,
                             "path": self.path_of.get(module, location.get("file")),
                             "detection": how, "status": status, "evidence_id": eid})

    def _declared_entries(self) -> None:
        for meta in self.metas:
            for group, items in (("cli", meta.get("scripts") or {}), ("ui", meta.get("gui_scripts") or {})):
                for nm, spec in items.items():
                    mod = str(spec).split(":")[0].strip()
                    self._add_entry(mod if mod in self.fact_of else None, group, "CONFIRMED",
                                    "declared console script", loc(file=meta["manifest"], symbol=f"{nm} = {spec}"), nm,
                                    str(spec).strip())
            for grp, items in (meta.get("entry_points") or {}).items():
                for nm, spec in items.items():
                    mod = str(spec).split(":")[0].strip()
                    self._add_entry(mod if mod in self.fact_of else None, "plugin-entry-point", "CONFIRMED",
                                    f"declared entry point group `{grp}`",
                                    loc(file=meta["manifest"], symbol=f"{nm} = {spec}"), nm)

    def _code_entries(self) -> None:
        for m in sorted(self.prod):
            f = self.fact_of[m]
            if PurePosixPath(f.path).name == "__main__.py":
                self._add_entry(m, "cli", "CONFIRMED", "__main__.py (python -m)", loc(file=f.path))
            elif f.main_guard_line:
                self._add_entry(m, "script", "CONFIRMED", "if __name__ == '__main__' guard",
                                loc(file=f.path, line=f.main_guard_line))
            for c in f.calls:
                if c.qualname.split(".")[0] in self.internal_tops:
                    continue
                det = next((d for d in self.cfg.entrypoint_detectors if _prefix_match(c.qualname, d["match"])), None)
                if det:
                    self._add_entry(m, det["type"], det["status"], f"{c.kind} `{c.qualname}`",
                                    loc(file=f.path, line=c.line, symbol=c.qualname))

    def _library_packages(self) -> list[str]:
        """Top-level packages that match a declared project name; else the largest top-level package."""
        tops = {m.split(".")[0] for m in self.prod
                if self.fact_of.get(m.split(".")[0]) and self.fact_of[m.split(".")[0]].is_package}
        names = {normalize_dist(m["name"]).replace("-", "_") for m in self.metas if m.get("name")}
        hits = sorted(t for t in tops if normalize_dist(t).replace("-", "_") in names)
        if hits or not tops:
            return hits
        size = Counter()
        for m in self.prod:
            size[m.split(".")[0]] += self.loc_of[m]
        return [max(tops, key=lambda t: size[t])]

    def phase_entrypoints(self) -> None:
        self.entries: list[dict] = []
        self._declared_entries()
        self._code_entries()
        has_pkg_manifest = any(PurePosixPath(x["path"]).name in ("pyproject.toml", "setup.py", "setup.cfg")
                               for x in self.fp.manifests)
        if has_pkg_manifest:
            for t in self._library_packages():
                f = self.fact_of.get(t)
                if f and f.is_package:
                    self._add_entry(t, "library-api", "SUPPORTED",
                                    "importable top-level package declared by a package manifest",
                                    loc(file=self.path_of[t], detail="defines __all__" if f.defines_all else None))
        if not self.entries:
            self.unknown("measure", "How is this code meant to be invoked?",
                         "No entry point of any recognized kind was found.")
        self.entry_modules = {e["module"] for e in self.entries if e["module"] in self.prod}
        self.reach = reachable(self.prod_adj, self.entry_modules)
        self.orphans = sorted(m for m in self.prod if self.fan_in[m] == 0 and m not in self.entry_modules
                              and not self.fact_of[m].is_package)
        if self.orphans:
            self.ev.add("measure", "graph.orphans", f"{len(self.orphans)} production modules are imported by no other "
                        "production module and are not recognized entry points", "CONFIRMED",
                        evidence=[loc(file=self.path_of[m]) for m in self.orphans],
                        data={"modules": self.orphans[:50]},
                        counter=[loc(detail="may be loaded dynamically, via plugins, or used only by tests")])

    # ---------------------------------------------------- signatures
    def _sites(self, s: Signature) -> tuple[list, list, dict]:
        """Import and call sites matching a signature, ignoring names that resolve to the repo's own modules."""
        imp_sites, call_sites, refined = [], [], defaultdict(list)
        internal = self.internal_tops
        for f in self.facts:
            for i in f.imports:
                if i.module.split(".")[0] in internal or i.relative:
                    continue
                names = [f"{i.module}.{n}" for n in i.names if n != "*"]
                if any(_prefix_match(x, p) for p in s.modules for x in [i.module, *names]):
                    imp_sites.append((f.module, i.line, i.module))
            for c in f.calls:
                if c.qualname.split(".")[0] in internal:
                    continue
                if any(_prefix_match(c.qualname, p) for p in s.modules):
                    call_sites.append((f.module, c.line, c.qualname))
                    for pref, prim in s.refine:
                        if c.qualname.startswith(pref):
                            refined[prim].append((f.module, c.line, c.qualname))
        return imp_sites, call_sites, refined

    def phase_signals(self) -> None:
        self.signals = []
        for s in self.cfg.signatures:
            sig = self._signal(s)
            if sig:
                self.signals.append(sig)
        by_prim = defaultdict(set)
        for sg in self.signals:
            if (sg["usage_level"] in ("CALLED", "IMPORTED") and sg["category"] in ("storage", "algorithm")
                    and sg["subcategory"] not in ("orm", "tabular-data", "serialization")):
                by_prim[sg["primitive"]].add((sg["library"], sg["evidence_id"]))
        for prim, libs in by_prim.items():
            if len({x[0] for x in libs}) > 1:
                self.unknown("measure", f"Which {prim} implementation is used in production?",
                             f"Multiple implementations are present: {', '.join(sorted({x[0] for x in libs}))}.",
                             data={"evidence_ids": sorted(x[1] for x in libs)})
        dyn = [s for s in self.signals if s["signature"] == "dynamic-import" and s["usage_level"] == "CALLED"]
        if dyn:
            self.unknown("measure", "Which modules are loaded dynamically at runtime?",
                         "importlib/`__import__` calls exist; the static import graph may be missing edges.",
                         data={"evidence_ids": [dyn[0]["evidence_id"]]})

    def _signal(self, s: Signature) -> dict | None:
        imp_sites, call_sites, refined = self._sites(s)
        # A declared distribution says nothing about which submodule (e.g. numpy.fft) is used.
        library_level = any("." not in p for p in s.modules)
        is_declared = library_level and bool(set(s.distributions) & self.declared_set)
        if not (imp_sites or call_sites or is_declared):
            return None
        prod, tests, path_of = self.prod, self.tests, self.path_of
        p_imp = [x for x in imp_sites if x[0] in prod]
        p_call = [x for x in call_sites if x[0] in prod]
        level = ("CALLED" if p_call else "IMPORTED" if p_imp else "DECLARED" if is_declared else "NON_PRODUCTION_ONLY")
        prod_mods = {x[0] for x in p_imp + p_call}
        sig = {
            "signature": s.id, "library": s.library, "category": s.category, "subcategory": s.subcategory,
            "primitive": s.primitive, "usage_level": level, "declared": is_declared,
            "production_import_sites": len(p_imp), "production_call_sites": len(p_call),
            "test_sites": len([x for x in imp_sites + call_sites if x[0] in tests]),
            "production_modules": sorted(prod_mods),
            "reachable_from_entrypoint": bool(prod_mods & self.reach) if self.entry_modules else None,
            "refined_primitives": {k: n for k, vs in refined.items() if (n := len([v for v in vs if v[0] in prod]))},
        }
        if level == "DECLARED":
            claim = f"{s.library} ({s.primitive}) is declared as a dependency but not imported by production code"
            locs = [loc(file=d.manifest, line=d.line, symbol=d.raw) for d in self.declared
                    if d.name in s.distributions and d.scope != "non-production"]
        elif level == "NON_PRODUCTION_ONLY":
            claim = f"{s.library} ({s.primitive}) appears only in tests/examples/scripts"
            locs = [loc(file=path_of[m], line=ln, symbol=q) for m, ln, q in imp_sites + call_sites]
        else:
            verb, n = ("calls", len(p_call)) if level == "CALLED" else ("imports", len(p_imp))
            claim = f"Production code {verb} {s.library} ({s.primitive}) at {n} site(s) in {len(prod_mods)} module(s)"
            locs = [loc(file=path_of[m], line=ln, symbol=q) for m, ln, q in (p_call or p_imp)]
        sig["evidence_id"] = self.ev.add("measure", f"signal.{s.category}", claim, "CONFIRMED", evidence=locs,
                                         data={k: v for k, v in sig.items() if k != "production_modules"},
                                         tool="repo-forensics/signatures")
        for prim, sites in refined.items():
            ps = [x for x in sites if x[0] in prod]
            if ps:
                self.ev.add("measure", f"signal.{s.category}.refined",
                            f"Production code constructs/calls {sorted({x[2] for x in ps})[0]} → {prim}", "CONFIRMED",
                            evidence=[loc(file=path_of[m], line=ln, symbol=q) for m, ln, q in ps],
                            data={"signature": s.id, "primitive": prim})
        return sig

    # ---------------------------------------------------- configuration and AI
    def phase_config_and_ai(self) -> None:
        env = defaultdict(list)
        for m in self.prod:
            for name, line in self.fact_of[m].env_vars:
                env[name].append((m, line))
        self.env_vars = sorted(env)
        if env:
            self.ev.add("measure", "config.env_vars", f"Production code reads {len(env)} environment variables",
                        "CONFIRMED", data={"names": self.env_vars},
                        evidence=[loc(file=self.path_of[s[0][0]], line=s[0][1], symbol=n) for n, s in sorted(env.items())])
            cfg_like = [n for n in self.env_vars if CONFIG_ENV_PATTERN.search(n.upper())]
            if cfg_like:
                self.unknown("measure", "Which concrete models/backends/endpoints are used when deployed?",
                             f"Behavior is selected at runtime via environment variables: {', '.join(cfg_like[:10])}.",
                             [loc(file=self.path_of[env[n][0][0]], line=env[n][0][1], symbol=n) for n in cfg_like])
        ai_sigs = [s for s in self.signals if s["category"] == "ai" or s["subcategory"] in ("vector-store", "vector-index")]
        active = [s for s in ai_sigs if s["usage_level"] in ("CALLED", "IMPORTED")]
        status = "AI_PRESENT" if active else "AI_DECLARED_OR_NON_PRODUCTION_ONLY" if ai_sigs else "NO_AI_SIGNATURE_FOUND"
        self.ai = {
            "status": status, "classification": "DEFERRED_TO_INFERENCE",
            "classification_options": ["AI_CORE", "AI_SUPPORTING", "NO_AI_FOUND", "UNKNOWN"],
            "components": [{k: s[k] for k in ("signature", "library", "subcategory", "primitive", "usage_level",
                                              "evidence_id")} for s in ai_sigs],
            "note": "Signature database is finite: NO_AI_SIGNATURE_FOUND is not proof of absence.",
        }

    # ============================================================ DECOMPOSE
    def phase_decompose(self) -> None:
        prod = self.prod
        self.mapping, self.method = comp_mod.plan({m: self.loc_of[m] for m in prod},
                                                  {m for m in prod if self.fact_of[m].is_package},
                                                  self.component_depth)
        self.cg = comp_mod.component_graph(self.mapping, self.prod_adj)
        depth = comp_mod.dependency_depth(self.cg) if self.cg else {}
        self.comp_cycles = cycles({c: set(v) for c, v in self.cg.items()})
        cg_it = comp_mod.component_graph(self.mapping, self.import_time_adj)
        self.comp_it_cycles = cycles({c: set(v) for c, v in cg_it.items()})
        synthetic = set(self.method["synthetic_buckets"])
        for c in self.comp_cycles:
            artefact = bool(synthetic & set(c))
            import_time = any(set(x) <= set(c) for x in self.comp_it_cycles)
            counter = []
            if artefact:
                counter.append(loc(detail="cycle passes through a merged bucket of small modules; "
                                   "may be an artefact of grouping"))
            if not import_time:
                counter.append(loc(detail="closed only by function-level (lazy) imports, often a deliberate cycle breaker"))
            shown = ", ".join(c[:6]) + ("…" if len(c) > 6 else "")
            eid = self.ev.add("decompose", "component.cycle",
                              f"{len(c)} components depend on each other cyclically: {shown}",
                              "CONFIRMED", counter=counter,
                              data={"members": c, "involves_synthetic_bucket": artefact, "import_time": import_time})
            label = ", ".join(c[:4]) + ("…" if len(c) > 4 else "")
            self.smell("component_cycle", label, f"{len(c)}-component cycle"
                       + (" at import time" if import_time else " via lazy imports only")
                       + (" (involves a merged bucket)" if artefact else ""),
                       eid, "warn" if import_time and not artefact else "info")
        self.test_edges = defaultdict(set)
        for t in self.tests:
            for d in self.full_adj.get(t, ()):
                if d in self.mapping:
                    self.test_edges[self.mapping[d]].add(t)
        self.ev.add("decompose", "component.method", "Directory structure is assumed to reflect component boundaries",
                    "INFERRED", data=self.method,
                    counter=[loc(detail="directories can be organizational rather than architectural; "
                                 "validate by reading entry points")])
        self.components = self._component_records(depth)
        self._repo_shape()

    def _component_records(self, depth: dict) -> list[dict]:
        members = defaultdict(list)
        for m, c in self.mapping.items():
            members[c].append(m)
        comp_signals = defaultdict(set)
        for sg in self.signals:
            for m in sg["production_modules"]:
                comp_signals[self.mapping.get(m)].add(sg["signature"])
        tp = defaultdict(Counter)
        for top, sites in self.graph.third_party.items():
            for s in sites:
                if s[0] in self.mapping:
                    tp[self.mapping[s[0]]][top] += 1
        out = []
        synthetic = set(self.method["synthetic_buckets"])
        for c in sorted(members, key=lambda c: -sum(self.loc_of[m] for m in members[c])):
            ms = sorted(members[c])
            dirs = sorted({str(PurePosixPath(self.path_of[m]).parent) for m in ms})
            files = sorted(self.path_of[m] for m in ms)
            rec = {
                "name": c, "synthetic": c in synthetic, "paths": (dirs if len(ms) > 1 else files)[:10],
                "modules": len(ms), "code_lines": sum(self.loc_of[m] for m in ms),
                "depends_on": dict(self.cg[c].most_common()),
                "depended_on_by": {o: self.cg[o][c] for o in self.cg if self.cg[o].get(c)},
                "dependency_depth": depth.get(c), "third_party": dict(tp[c].most_common(8)),
                "signals": sorted(comp_signals.get(c, set())),
                "entrypoints": sorted({e["type"] for e in self.entries if e["module"] in ms}),
                "imported_by_tests": len(self.test_edges.get(c, ())),
                "in_component_cycle": any(c in x for x in self.comp_cycles),
                "responsibility": None,
            }
            rec["evidence_id"] = self.ev.add(
                "decompose", "component",
                f"Component `{c}`: {rec['modules']} modules, {rec['code_lines']} code lines, depends on "
                f"{len(rec['depends_on'])} and is used by {len(rec['depended_on_by'])} components", "CONFIRMED",
                evidence=[loc(file=p) for p in rec["paths"]], data={k: v for k, v in rec.items() if k != "responsibility"})
            if rec["imported_by_tests"] == 0 and self.tests:
                self.smell("component_without_direct_tests", c, "no test module imports any of its modules",
                           rec["evidence_id"], "info")
            out.append(rec)
        return out

    def _repo_shape(self) -> None:
        etypes = Counter(e["type"] for e in self.entries)
        labels = [("http", "service (HTTP)"), ("worker", "background worker"), ("mcp-server", "MCP server"),
                  ("ui", "UI application"), ("cli", "CLI application")]
        shape = [lab for t, lab in labels if etypes.get(t)]
        if etypes.get("library-api"):
            shape.append("library (importable package)")
        if not shape and etypes.get("script"):
            shape.append("collection of scripts")
        self.shape, self.shape_eid = shape, None
        if shape:
            self.shape_eid = self.ev.add("decompose", "repo.shape", f"Repository appears to be: {', '.join(shape)}",
                                         "INFERRED", data={"entrypoint_types": dict(etypes),
                                                           "supporting_evidence": [e["evidence_id"] for e in self.entries]})

    # ---------------------------------------------------- complexity (tier 1)
    def phase_complexity(self) -> None:
        self.complexity, self.funcs = {"status": "not_measured"}, []
        lizard = None
        if self.tier >= 1:
            try:
                import lizard  # type: ignore
            except ImportError:
                self.notes.append("lizard not installed: complexity not measured (pip install 'repo-forensics[complexity]')")
        if lizard is None:
            self.unknown("measure", "How complex are the functions?", "Complexity not measured (tier 0 or lizard missing).")
            return
        for m in sorted(self.prod):
            p = self.path_of[m]
            try:
                info = lizard.analyze_file.analyze_source_code(
                    p, (self.acq.root / p).read_text(encoding="utf-8", errors="replace"))
            except Exception as e:  # lizard can fail on exotic syntax: record, never crash
                self.notes.append(f"lizard failed on {p}: {type(e).__name__}")
                continue
            self.funcs += [{"module": m, "component": self.mapping.get(m), "file": p, "function": fn.name,
                            "line": fn.start_line, "cc": fn.cyclomatic_complexity, "nloc": fn.nloc,
                            "params": fn.parameter_count} for fn in info.function_list]
        self._complexity_summary(getattr(lizard, "version", ""))

    def _complexity_summary(self, version: str) -> None:
        th, funcs = self.th, self.funcs
        ccs = [f["cc"] for f in funcs]
        self.complexity = {"status": "measured", "tool": f"lizard {version}".strip(),
                           "scope": "production Python modules", "functions": len(funcs),
                           "cyclomatic": distribution(ccs), "nloc": distribution([f["nloc"] for f in funcs]),
                           **{f"functions_cc_gt_{b}": sum(1 for x in ccs if x > b) for b in th["complexity_buckets"]},
                           "hotspots": sorted(funcs, key=lambda f: -f["cc"])[: th["max_hotspots"]]}
        cyc = self.complexity["cyclomatic"]
        self.ev.add("measure", "complexity.distribution", f"{len(funcs)} functions: median CC {cyc.get('median')}, "
                    f"P95 {cyc.get('p95')}, max {cyc.get('max')}", "CONFIRMED", tool="lizard",
                    data={k: v for k, v in self.complexity.items() if k != "hotspots"})
        high = [f for f in sorted(funcs, key=lambda f: -f["cc"]) if f["cc"] > th["high_complexity_cc"]]
        cap = th.get("max_complexity_signals", 15)
        if len(high) > cap:
            rest = high[cap:]
            eid = self.ev.add("measure", "complexity.function.aggregate",
                              f"{len(rest)} further functions exceed cyclomatic complexity {th['high_complexity_cc']}",
                              "CONFIRMED", tool="lizard",
                              evidence=[loc(file=f["file"], line=f["line"], symbol=f"{f['function']} (CC {f['cc']})")
                                        for f in rest])
            self.smell("high_complexity", f"{len(rest)} more functions", f"CC {rest[-1]['cc']}–{rest[0]['cc']}",
                       eid, "info")
        for f in high[:cap]:
            eid = self.ev.add("measure", "complexity.function",
                              f"{f['module']}::{f['function']} has cyclomatic complexity {f['cc']}", "CONFIRMED",
                              evidence=[loc(file=f["file"], line=f["line"], symbol=f["function"])], tool="lizard", data=f)
            self.smell("high_complexity", f"{f['module']}::{f['function']}", f"CC {f['cc']}, {f['nloc']} NLOC", eid,
                       "warn" if f["cc"] > th["very_high_complexity_cc"] else "info")

    # ---------------------------------------------------- tests
    def phase_tests(self) -> None:
        tests, loc_of = self.tests, self.loc_of
        t_lines = sum(loc_of[m] for m in tests)
        p_lines = sum(loc_of[m] for m in self.prod)
        fw = Counter(i.module.split(".")[0] for t in tests for i in self.fact_of[t].imports
                     if i.module.split(".")[0] in TEST_FRAMEWORKS)
        if any(PurePosixPath(self.path_of[t]).name == "conftest.py" for t in tests):
            fw["pytest"] += 1
        comps = {c["name"] for c in self.components}
        self.tests_rep = {
            "test_modules": len(tests), "test_functions": sum(self.fact_of[t].test_functions for t in tests),
            "test_code_lines": t_lines, "production_code_lines": p_lines,
            "test_to_production_ratio": round(t_lines / p_lines, 3) if p_lines else None,
            "frameworks": sorted(fw), "components_imported_by_tests": sorted(self.test_edges),
            "components_not_imported_by_tests": sorted(comps - set(self.test_edges)),
            "note": "Static inventory only: 'imported by tests' is not coverage.",
        }
        self.ev.add("measure", "tests.inventory", f"{len(tests)} test modules with {self.tests_rep['test_functions']} "
                    f"test functions; test/production code ratio {self.tests_rep['test_to_production_ratio']}",
                    "CONFIRMED", data=self.tests_rep)
        if self.tier < 2:
            self.unknown("measure", "Do the tests pass, and what do they cover?",
                         "Tier 0/1 never executes repository code; coverage requires a sandboxed Tier 2 run.")
        self.unknown("measure", "How much code is duplicated?", "Duplication analysis is not implemented in v0.1.")

    # ============================================================== REPORT
    def assemble(self) -> dict:
        acq, fp, mg_prod = self.acq, self.fp, self.prod
        rows = [{"module": m, "path": self.path_of[m], "component": self.mapping.get(m), "code_lines": self.loc_of[m],
                 "fan_in": self.fan_in[m], "fan_out": self.fan_out[m], "is_package": self.fact_of[m].is_package,
                 "reachable_from_entrypoint": (m in self.reach) if self.entry_modules else None}
                for m in sorted(mg_prod)]
        graph_json = {
            "nodes": rows + [{"module": t, "path": self.path_of[t], "component": "(tests)",
                              "code_lines": self.loc_of[t]} for t in sorted(self.tests)],
            "edges": [{"src": e.src, "dst": e.dst, "line": e.line, "kind": e.kind, "resolution": e.resolution}
                      for e in self.graph.edges],
            "components": {c: dict(v) for c, v in self.cg.items()},
        }
        measured = self.complexity["status"] == "measured"
        tier_done = 2 if (self.dyn and self.dyn["status"] != "failed") else (1 if (measured or any(
            t.status == "ok" for t in self.tool_runs.values())) else 0)
        if self.dyn and (self.dyn["status"] == "failed" or not (self.dyn.get("tests") or {}).get("ran")):
            self.unknown("dynamic", "Do the tests pass, and what do they cover?",
                         "The Tier 2 run did not complete a test run; this is missing data, not evidence of no execution.")
        report = {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": "repo-forensics", "version": __version__, "tier": tier_done,
                     "requested_tier": self.tier, "notes": self.notes},
            "provenance": {"url": acq.url, "commit_sha": acq.commit_sha, "requested_ref": acq.requested_ref,
                           "default_branch": acq.default_branch, "dirty": acq.dirty, "analyzed_at": acq.analyzed_at,
                           "license": self.spdx, "license_file": self.lic_file,
                           "pinned": bool(acq.commit_sha and not acq.dirty)},
            "fingerprint": {"languages": fp.languages, "analysis_coverage": self.analysis_coverage,
                            "file_classes": fp.file_classes, "files_total": len(fp.files),
                            "manifests": fp.manifests, "build_systems": fp.build_systems,
                            "package_roots": fp.package_roots, "multi_package": fp.multi_package, "ci": fp.ci},
            "entrypoints": self.entries,
            "repo_shape": {"hypothesis": self.shape, "status": "INFERRED" if self.shape else "UNKNOWN",
                           "evidence_id": self.shape_eid},
            "dependencies": {
                "declared": [{"name": d.name, "scope": d.scope, "manifest": d.manifest, "raw": d.raw}
                             for d in self.declared],
                "declared_counts": {k: len(v) for k, v in self.declared_by_scope.items()},
                "third_party_imported": self.third_party,
                "stdlib_imported": dict(sorted(self.graph.stdlib.items(), key=lambda kv: -kv[1])),
                "imported_not_declared": sorted(self.undeclared),
                "declared_not_imported": getattr(self, "unused", []),
            },
            "module_graph": {
                "production_modules": len(mg_prod), "test_modules": len(self.tests),
                "edges": sum(len(v) for v in self.prod_adj.values()),
                "fan_in": distribution(self.fi_vals), "fan_out": distribution(self.fo_vals),
                "module_code_lines": distribution(self.loc_vals),
                "cycles": self.rt_cycles, "import_time_cycles": self.it_cycles,
                "hubs": [{"module": m, "fan_in": self.fan_in[m]} for m in self.hubs],
                "top_fan_out": [{"module": m, "fan_out": self.fan_out[m]}
                                for m in sorted(mg_prod, key=lambda m: -self.fan_out[m])[: self.th["max_hotspots"]]],
                "orphans": self.orphans,
                "reachable_from_entrypoints": len(self.reach) if self.entry_modules else None,
            },
            "components": {"method": self.method, "items": self.components, "cycles": self.comp_cycles,
                           "import_time_cycles": self.comp_it_cycles},
            "signals": sorted(self.signals, key=lambda s: (s["category"], USAGE_ORDER.index(s["usage_level"]), s["signature"])),
            "ai": self.ai,
            "config": {"env_vars": self.env_vars},
            "complexity": self.complexity,
            "duplication": {"status": "not_implemented"},
            "toolchain": [t.summary() for t in self.tool_runs.values()],
            "dynamic": self._dynamic_summary(),
            "fusion": self.fusion,
            "tests": self.tests_rep,
            "smells": self.smells,
            "architecture_hypotheses": [],
            "unknowns": self.unknowns,
            "checklist": self.checklist(),
            "evidence_summary": self.ev.by_status(),
            "_graph": graph_json,
            "_functions": self.funcs,
        }
        return report

    def _dynamic_summary(self) -> dict:
        if not self.dyn:
            return {"status": "not_run", "reason": "tier < 2"}
        d = self.dyn
        t = dict(d.get("tests") or {})
        cov = t.pop("coverage", None) or {}
        cg = t.pop("callgraph", None) or {}
        t["coverage_percent"] = (cov.get("totals") or {}).get("percent_covered")
        t["callgraph_edges"] = len(cg.get("edges", []))
        return {"status": d["status"], "isolation": d["isolation"], "python": d["python"], "elapsed_s": d["elapsed_s"],
                "install": d["install"], "tests": t,
                "entry_probes": [{"spec": p["spec"], "status": p["status"], "loaded_files": len(p["loaded_files"]),
                                  "edges": len(p["edges"])} for p in d["entry_probes"]],
                "deptry": {"status": d["deptry"].get("status"), "issues": len(d["deptry"].get("issues", []))},
                "mypy": {k: v for k, v in (d.get("mypy") or {}).items() if k != "by_file"},
                "steps": [{k: v for k, v in s.items() if k not in ("stdout_tail",)} for s in d["steps"]]}

    def checklist(self) -> list[dict]:
        def g(gate, status, note=""):
            return {"gate": gate, "status": status, "note": note}
        pinned = bool(self.acq.commit_sha and not self.acq.dirty)
        return [
            g("Repository pinned to commit", "done" if pinned else "partial", "" if pinned else "no clean git SHA"),
            g("Languages identified", "done"),
            g("Build systems identified", "done" if self.fp.build_systems else "partial"),
            g("Entry points located", "done" if self.entries else "partial", "Python only"),
            g("Internal modules mapped", "done", "Python only"),
            g("Dependency inventory generated", "done", "direct Python deps only; SBOM/transitive in v0.2"),
            g("Dependency graph generated", "done"),
            g("Cycles calculated", "done"),
            g("Fan-in/fan-out calculated", "done"),
            g("Components inferred", "partial", "directory-based; responsibilities deferred to inference step"),
            g("External boundaries mapped", "done", "signature-based"),
            g("Storage mechanisms mapped", "done", "signature-based"),
            g("Computational primitives identified", "done", "signature-based; CENTRAL level deferred to inference"),
            g("AI/ML usage identified", "partial", "presence measured; core vs supporting deferred to inference"),
            g("Complexity measured", "done" if self.complexity["status"] == "measured" else "not_done"),
            g("Duplication measured", "not_done", "planned"),
            g("External static analyzers run", "done" if any(t.status == "ok" for t in self.tool_runs.values())
              else "not_done", ", ".join(f"{k}:{t.status}" for k, t in self.tool_runs.items()) or "tier < 1"),
            g("Dynamic run (tests, entry probes)", ("done" if self.dyn["status"] == "ok" else "partial")
              if self.dyn else "not_done", "process-level sandbox" if self.dyn else "tier < 2"),
            g("Independent methods fused", "done" if self.fusion else "not_done",
              f"{len(self.fusion.get('claims', []))} fused claims" if self.fusion else ""),
            g("Tests inventoried", "done", "static + executed" if self.dyn else "static only"),
            g("Architecture patterns hypothesized", "deferred_to_inference"),
            g("Architecture smells identified", "done", "signals, not verdicts"),
            g("Evidence confidence attached", "done"),
            g("Counter-evidence recorded", "partial", "mechanical counter-evidence only; hypotheses must add their own"),
            g("Unknowns explicitly listed", "done"),
        ]
