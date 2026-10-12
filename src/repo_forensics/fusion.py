"""Fusion: combine independent methods into calibrated claims.

Rules of evidence used here:
1. A tool finding is a fact about the tool's output, not about the code.
2. Agreement only counts when methods are independent. ruff F401 and vulture's unused-import
   check are both name-binding analyses: their agreement is one method, not two.
3. Static analysis says what MAY happen; a run says what DID happen. One observed execution
   refutes "never used"; absence of execution in one run is only weak support for it.
4. Every dynamic claim names its run; a failed or partial run is never read as "nothing ran".
"""

from __future__ import annotations

import ast
from collections import Counter, defaultdict

from .dynamic.sandbox import aggregate_edges, module_of_path
from .evidence import loc

DEF_KINDS = {"function", "method", "property"}


def _def_ranges(root, path: str, cache: dict) -> dict[int, tuple[int, int]]:
    """def line -> (first body line, last line) for every function in a file."""
    if path not in cache:
        rng = {}
        try:
            tree = ast.parse((root / path).read_bytes())
            for n in ast.walk(tree):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.body:
                    span = (n.body[0].lineno, n.end_lineno or n.body[-1].lineno)
                    rng[n.lineno] = span
                    if n.decorator_list:  # vulture reports decorated functions at their first decorator line
                        rng[min(d.lineno for d in n.decorator_list)] = span
        except (SyntaxError, ValueError, OSError):
            pass
        cache[path] = rng
    return cache[path]


class Fusion:
    def __init__(self, an, tools: dict, dyn: dict | None):
        self.an, self.tools, self.dyn = an, tools, dyn
        self.ev = an.ev
        self.p2m = module_of_path(an)
        self.claims: list[dict] = []
        self.cov_files = {}
        if dyn and (dyn.get("tests") or {}).get("coverage"):
            self.cov_files = {k.replace("\\", "/").lstrip("./"): v for k, v in dyn["tests"]["coverage"]["files"].items()}
        self.loaded_runtime: dict[str, list[str]] = defaultdict(list)  # module -> entry specs that loaded it
        for probe in (dyn or {}).get("entry_probes", []):
            for f in probe["loaded_files"]:
                m = self.p2m.get(f)
                if m:
                    self.loaded_runtime[m].append(probe["spec"])
        self.dynamic_ok = bool(dyn) and dyn.get("status") in ("ok", "partial")
        self.plugin_loading = any(
            s["signature"] in ("plugin-system", "dynamic-import") and s["usage_level"] == "CALLED" for s in an.signals
        )

    def claim(self, rule, verdict, claim, status, locations, data=None, counter=None, conf=None, source="fusion"):
        eid = self.ev.add(
            "fusion",
            f"fusion.{rule}",
            claim,
            status,
            evidence=locations,
            counter=counter,
            confidence=conf,
            tool="repo-forensics/fusion",
            source=source,
            data={"verdict": verdict, **(data or {})},
        )
        self.claims.append({"rule": rule, "verdict": verdict, "claim": claim, "status": status, "evidence_id": eid})
        return eid

    # ---------------------------------------------------------- R1 dead code
    def dead_code(self) -> dict:
        vt = self.tools.get("vulture")
        if not vt or vt.status != "ok":
            return {"status": "not_run"}
        cache: dict = {}
        lib_tops = {e["module"] for e in self.an.entries if e["type"] == "library-api"}
        counts: Counter = Counter()
        shown: Counter = Counter()
        for f in vt.findings:
            if f.kind not in DEF_KINDS or not f.file:
                counts["not-a-callable (imports/variables: name-binding only)"] += 1
                continue
            mod = self.p2m.get(f.file)
            if mod not in self.an.prod:
                continue
            rng = _def_ranges(self.an.acq.root, f.file, cache).get(f.line)
            executed = None
            cov = self.cov_files.get(f.file)
            if cov is not None and rng:
                lines = set(cov.get("executed_lines", []))
                executed = any(ln in lines for ln in range(rng[0], rng[1] + 1))
            public = mod in lib_tops and not (f.symbol or "").startswith("_")
            where = [loc(file=f.file, line=f.line, symbol=f.symbol, detail=f"vulture {f.confidence:.0%}")]
            if executed:
                verdict, status, text = (
                    "refuted",
                    "CONFIRMED",
                    (f"vulture reports {f.symbol} unused, but its body executed during the test run"),
                )
            elif public:
                verdict, status, text = (
                    "public-api",
                    "INFERRED",
                    (f"{f.symbol} is unused inside the repository but exported by library package {mod}"),
                )
            elif executed is False and not self.plugin_loading:
                verdict, status, text = (
                    "likely-dead",
                    "SUPPORTED",
                    (f"{f.symbol}: unused by name (vulture) and never executed in the test run"),
                )
            elif executed is False:
                verdict, status, text = (
                    "possibly-dead",
                    "INFERRED",
                    (f"{f.symbol}: unused by name and not executed, but the repo loads code dynamically"),
                )
            else:
                verdict, status, text = "unverified", "INFERRED", f"{f.symbol}: unused by name (vulture only; no run data)"
            counts[verdict] += 1
            if shown[verdict] < 25:
                shown[verdict] += 1
                counter = []
                if public:
                    counter.append(loc(detail="part of the library's public surface"))
                if self.plugin_loading and verdict != "refuted":
                    counter.append(loc(detail="plugin or dynamic-import loading present"))
                self.claim(
                    "dead_code",
                    verdict,
                    text,
                    status,
                    where,
                    counter=counter,
                    data={"symbol": f.symbol, "module": mod, "vulture_confidence": f.confidence, "executed_in_tests": executed},
                    conf=0.7 if status == "SUPPORTED" else None,
                    source="fusion(static+dynamic)" if executed is not None else "fusion(static)",
                )
        return {"status": "ok", "verdicts": dict(counts), "run_data": bool(self.cov_files)}

    # ---------------------------------------------------------- R2 module reachability
    def reachability(self) -> dict:
        res = {"orphans_loaded_at_runtime": [], "orphans_unused": [], "signals_reached_at_runtime": []}
        if not self.dynamic_ok:
            return {"status": "not_run"}
        for m in self.an.orphans:
            path = self.an.path_of[m]
            cov = self.cov_files.get(path)
            if self.loaded_runtime.get(m):
                eid = self.claim(
                    "reachability",
                    "loaded-dynamically",
                    f"{m} has no static importer but was loaded at runtime by {', '.join(sorted(set(self.loaded_runtime[m])))}",
                    "CONFIRMED",
                    [loc(file=path)],
                    data={"module": m},
                    source="dynamic",
                )
                res["orphans_loaded_at_runtime"].append({"module": m, "evidence_id": eid})
            elif cov is not None and not cov.get("executed_lines"):
                eid = self.claim(
                    "reachability",
                    "likely-unused-module",
                    f"{m}: no static importer, not loaded by entry points, no line executed in tests",
                    "SUPPORTED",
                    [loc(file=path)],
                    data={"module": m},
                    conf=0.7,
                )
                res["orphans_unused"].append({"module": m, "evidence_id": eid})
        for s in self.an.signals:
            if s.get("reachable_from_entrypoint") is False:
                hits = sorted({spec for m in s["production_modules"] for spec in self.loaded_runtime.get(m, [])})
                if hits:
                    eid = self.claim(
                        "reachability",
                        "reached-at-runtime",
                        f"{s['library']} ({s['primitive']}) is not statically reachable, yet its modules "
                        f"were loaded at runtime by {', '.join(hits)}",
                        "CONFIRMED",
                        [loc(file=self.an.path_of[m]) for m in s["production_modules"]],
                        data={"signature": s["signature"]},
                        source="dynamic",
                    )
                    s["runtime_reachable"] = True
                    s["runtime_evidence_id"] = eid
                    res["signals_reached_at_runtime"].append(s["signature"])
        res["status"] = "ok"
        return res

    # ---------------------------------------------------------- R3 hidden coupling / dispatch
    def coupling(self) -> dict:
        if not self.dynamic_ok:
            return {"status": "not_run"}
        edges = list(((self.dyn.get("tests") or {}).get("callgraph") or {}).get("edges", []))
        for p in self.dyn.get("entry_probes", []):
            edges += p.get("edges", [])
        mod_edges, external = aggregate_edges(edges, self.p2m)
        static = {(e.src, e.dst) for e in self.an.graph.edges}
        # `from pkg import name` binds to the package; the call lands in the submodule that defines name.
        # A path through a package __init__ (re-export) is static coupling, not hidden coupling.
        pkgs = {m for m, f in self.an.fact_of.items() if f.is_package}
        via_pkg = {(s, d) for (s, p) in static if p in pkgs for (p2, d) in static if p2 == p}
        parents = {(s, d) for (s, p) in static for d in self.an.prod if p in pkgs and d.startswith(p + ".")}
        static |= via_pkg | parents
        prod = self.an.prod
        hidden = {
            k: n for k, n in mod_edges.items() if k[0] in prod and k[1] in prod and k not in static and (k[1], k[0]) not in static
        }
        comp = self.an.mapping
        comp_hidden: Counter = Counter()
        for (a, b), n in hidden.items():
            if comp.get(a) != comp.get(b):
                comp_hidden[(comp.get(a), comp.get(b))] += n
        if hidden:
            top = sorted(hidden.items(), key=lambda kv: -kv[1])[:15]
            self.claim(
                "coupling",
                "runtime-only-edges",
                f"{len(hidden)} module pairs called each other at runtime without any static import between them",
                "CONFIRMED",
                [loc(file=self.an.path_of[a], symbol=f"{a} -> {b}", detail=f"{n} calls") for (a, b), n in top],
                data={"pairs": len(hidden), "component_pairs": len(comp_hidden)},
                source="dynamic",
                counter=[
                    loc(
                        detail="calls through objects passed as arguments need no import; this is "
                        "coupling the static graph cannot see, not necessarily a defect"
                    )
                ],
            )
        dispatch = Counter()
        for (src, dmod), n in external.items():
            if dmod in prod and src not in (
                "<external:__main__>",
                "<external:_pytest>",
                "<external:pytest>",
                "<external:_frozen_importlib>",
                "<external:importlib>",
                "<external:rf_entry_probe>",
            ):
                dispatch[(src, comp.get(dmod))] += n
        for (src, c), n in dispatch.most_common(8):
            self.claim(
                "coupling",
                "external-dispatch",
                f"Code in component {c} is entered from {src[10:-1]} ({n} calls): "
                "control passes through a third-party dispatcher",
                "CONFIRMED",
                [loc(detail=f"{src} -> {c}")],
                data={"dispatcher": src, "component": c, "calls": n},
                source="dynamic",
            )
        return {
            "status": "ok",
            "runtime_only_module_pairs": len(hidden),
            "runtime_only_component_pairs": [{"from": a, "to": b, "calls": n} for (a, b), n in comp_hidden.most_common(10)],
            "external_dispatchers": [
                {"dispatcher": s[10:-1], "component": c, "calls": n} for (s, c), n in dispatch.most_common(8)
            ],
        }

    # ---------------------------------------------------------- R4 dependencies
    def dependencies(self) -> dict:
        d = (self.dyn or {}).get("deptry") or {}
        if d.get("status") != "ok":
            return {"status": "not_run"}
        by_code = defaultdict(set)
        for issue in d["issues"]:
            code = issue["error"]["code"]
            by_code[code].add(issue["module"])
        ours_unused = set(getattr(self.an, "unused", []))
        ours_missing = set(self.an.undeclared)
        res = {"status": "ok", "counts": {k: len(v) for k, v in by_code.items()}}
        both_unused = sorted(
            m for m in by_code.get("DEP002", set()) if m.replace("_", "-").lower() in ours_unused or m in ours_unused
        )
        marked = {d.name for d in self.an.declared if ";" in d.raw and "platform" in d.raw}
        for pkg in both_unused:
            conditional = pkg.replace("_", "-").lower() in marked
            self.claim(
                "dependencies",
                "unused-two-methods",
                f"{pkg} is declared but unused according to both deptry and the static import scan",
                "INFERRED" if conditional else "SUPPORTED",
                [loc(detail="deptry DEP002 + repo-forensics declared_not_imported")],
                data={"package": pkg, "platform_conditional": conditional},
                conf=None if conditional else 0.8,
                counter=[
                    loc(
                        detail="platform-conditional requirement: may provide a module under another name on "
                        "that platform; both methods share the name-mapping blind spot"
                    )
                ]
                if conditional
                else [],
            )
        if by_code.get("DEP003"):
            self.claim(
                "dependencies",
                "transitive-imports",
                f"Imported directly but installed only as transitive dependencies: {', '.join(sorted(by_code['DEP003'])[:12])}",
                "SUPPORTED",
                [loc(detail="deptry DEP003 in the installed environment")],
                data={"packages": sorted(by_code["DEP003"])},
                conf=0.85,
                source="dynamic(environment)",
            )
        missing = sorted(by_code.get("DEP001", set()))
        if missing:
            agree = sorted(set(missing) & ours_missing)
            self.claim(
                "dependencies",
                "missing",
                f"Imported but not declared (deptry): {', '.join(missing[:12])}",
                "SUPPORTED" if agree else "INFERRED",
                [loc(detail="deptry DEP001")],
                data={"packages": missing, "agrees_with_static_scan": agree},
            )
        return res

    # ---------------------------------------------------------- R5 security, R6 tests, R7 types
    def security(self) -> dict:
        bt = self.tools.get("bandit")
        if not bt or bt.status != "ok":
            return {"status": "not_run"}
        by_rule = defaultdict(list)
        for f in bt.findings:
            by_rule[(f.rule, f.symbol, f.level)].append(f)
        out = []
        for (rule, name, sev), fs in sorted(
            by_rule.items(), key=lambda kv: ({"high": 0, "medium": 1, "low": 2}.get(kv[0][2], 3), -len(kv[1]))
        ):
            conf = max((f.confidence or 0) for f in fs)
            status = "SUPPORTED" if sev == "high" and conf >= 0.9 else "INFERRED"
            eid = self.ev.add(
                "toolchain",
                "tool.bandit",
                f"bandit {rule} ({name}, severity {sev}) at {len(fs)} location(s)",
                status,
                evidence=[loc(file=f.file, line=f.line, detail=f.message[:120]) for f in fs],
                tool="bandit",
                data={"rule": rule, "severity": sev, "max_confidence": conf, "cwe": fs[0].extra.get("cwe")},
            )
            out.append({"rule": rule, "name": name, "severity": sev, "count": len(fs), "status": status, "evidence_id": eid})
        return {"status": "ok", "rules": out}

    def tests_and_types(self) -> dict:
        if not self.dynamic_ok:
            return {"status": "not_run"}
        t = self.dyn.get("tests") or {}
        comp_cov: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for path, v in self.cov_files.items():
            m = self.p2m.get(path)
            c = self.an.mapping.get(m)
            if c:
                s = v.get("summary", {})
                comp_cov[c][0] += s.get("covered_lines", 0)
                comp_cov[c][1] += s.get("num_statements", 0)
        comp_pct = {c: round(100 * a / b, 1) for c, (a, b) in comp_cov.items() if b}
        if t.get("ran"):
            total = (t.get("coverage") or {}).get("totals", {}).get("percent_covered")
            cov_txt = f"line coverage {total:.1f}%" if total is not None else "no coverage data"
            self.claim(
                "tests",
                "run",
                f"Test run: {t.get('tests', '?')} tests, {t.get('failures', '?')} failures, "
                f"{t.get('errors', '?')} errors, {t.get('skipped', '?')} skipped; {cov_txt}",
                "CONFIRMED",
                [loc(detail="pytest + coverage.py in the Tier 2 sandbox")],
                data={"by_component": comp_pct},
                source="dynamic",
            )
        my = self.dyn.get("mypy") or {}
        if my.get("status") == "ok":
            kloc = max(sum(self.an.loc_of[m] for m in self.an.prod) / 1000, 0.001)
            self.claim(
                "types",
                "mypy",
                f"mypy (dependencies installed) reports {my['errors']} errors ({my['errors'] / kloc:.1f} per 1k code lines)",
                "CONFIRMED",
                [loc(file=f, detail=f"{n} errors") for f, n in sorted(my["by_file"].items(), key=lambda kv: -kv[1])[:10]],
                data={"by_code": my.get("by_code")},
                source="dynamic(environment)",
            )
        return {"status": "ok", "coverage_by_component": comp_pct}

    def run(self) -> dict:
        return {
            "rules": {
                "dead_code": self.dead_code(),
                "reachability": self.reachability(),
                "coupling": self.coupling(),
                "dependencies": self.dependencies(),
                "security": self.security(),
                "tests_types": self.tests_and_types(),
            },
            "claims": self.claims,
            "principles": __doc__.split("Rules of evidence used here:")[1].strip(),
        }


__all__ = ["Fusion"]
