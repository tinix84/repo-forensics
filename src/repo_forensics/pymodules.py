"""Python module naming and internal import-graph construction."""

from __future__ import annotations

import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from .pyparse import FileFacts

STDLIB = set(sys.stdlib_module_names) | {"__future__", "_typeshed"}


def python_roots(py_files: list[str], manifest_paths: list[str], all_dirs: set[str]) -> list[str]:
    """Import roots: repo root, `src/`, and each Python package-manifest dir (+ its src/)."""
    roots = {""}
    if "src" in all_dirs:
        roots.add("src")
    for m in manifest_paths:
        p = PurePosixPath(m)
        if p.name in ("pyproject.toml", "setup.py", "setup.cfg"):
            d = str(p.parent)
            d = "" if d == "." else d
            roots.add(d)
            sd = f"{d}/src" if d else "src"
            if sd in all_dirs:
                roots.add(sd)
    return sorted(roots, key=lambda r: (-len(r), r))


def module_name(path: str, roots: list[str]) -> tuple[str, bool]:
    """Return (dotted module name, is_package) using the deepest matching root."""
    for r in roots:  # roots sorted deepest first
        if r == "" or path.startswith(r + "/"):
            rel = path[len(r) + 1:] if r else path
            break
    else:  # pragma: no cover
        rel = path
    p = PurePosixPath(rel)
    parts = list(p.parts[:-1])
    stem = p.name.rsplit(".", 1)[0]
    is_pkg = stem == "__init__"
    if not is_pkg:
        parts.append(stem)
    return ".".join(parts), is_pkg


@dataclass
class Edge:
    src: str
    dst: str
    line: int
    kind: str              # module | lazy | type_checking
    resolution: str        # exact | prefix | from-name | sibling


@dataclass
class ModuleGraph:
    modules: dict[str, FileFacts]                       # module -> facts
    path_to_module: dict[str, str]
    edges: list[Edge] = field(default_factory=list)
    third_party: dict[str, list[tuple[str, int, str]]] = field(default_factory=dict)  # top -> [(module, line, full, kind)]
    stdlib: dict[str, int] = field(default_factory=dict)
    unresolved_internal: list[tuple[str, str, int]] = field(default_factory=list)
    unresolved_relative: list[tuple[str, str, int]] = field(default_factory=list)

    def adjacency(self, kinds: tuple[str, ...] = ("module", "lazy")) -> dict[str, set[str]]:
        adj: dict[str, set[str]] = {m: set() for m in self.modules}
        for e in self.edges:
            if e.kind in kinds and e.src != e.dst:
                adj[e.src].add(e.dst)
        return adj


def build_graph(facts: list[FileFacts]) -> ModuleGraph:
    modules = {f.module: f for f in facts if f.module}
    g = ModuleGraph(modules=modules, path_to_module={f.path: f.module for f in facts})
    internal_tops = {m.split(".")[0] for m in modules}
    third: dict[str, list] = defaultdict(list)
    stdlib: dict[str, int] = defaultdict(int)

    def longest_prefix(target: str) -> str | None:
        parts = target.split(".")
        for i in range(len(parts), 0, -1):
            cand = ".".join(parts[:i])
            if cand in modules:
                return cand
        return None

    for f in facts:
        pkg_parts = f.module.split(".") if f.is_package else f.module.split(".")[:-1]
        for imp in f.imports:
            if imp.unresolved:
                g.unresolved_relative.append((f.module, imp.module, imp.line))
                continue
            targets: list[tuple[str, str]] = []
            if imp.names and imp.names != ["*"]:
                for n in imp.names:
                    full = f"{imp.module}.{n}" if imp.module else n
                    if full in modules:
                        targets.append((full, "from-name"))
                if not targets and imp.module:
                    targets.append((imp.module, "exact"))
            else:
                targets.append((imp.module, "exact"))
            for target, how in targets:
                if not target:
                    continue
                dst = target if target in modules else longest_prefix(target)
                if dst:
                    g.edges.append(Edge(f.module, dst, imp.line, imp.kind,
                                        how if dst == target else "prefix"))
                    continue
                # implicit sibling import (scripts / tests run with their dir on sys.path)
                parent = ".".join(pkg_parts)
                parent_is_pkg = parent in modules and modules[parent].is_package
                if not imp.relative and pkg_parts and not parent_is_pkg:
                    sib = ".".join(pkg_parts + [target])
                    sdst = longest_prefix(sib) if sib else None
                    if sdst and sdst != f.module:
                        g.edges.append(Edge(f.module, sdst, imp.line, imp.kind, "sibling"))
                        continue
                top = target.split(".")[0]
                if imp.relative or top in internal_tops:
                    g.unresolved_internal.append((f.module, target, imp.line))
                elif top in STDLIB:
                    stdlib[top] += 1
                else:
                    third[top].append((f.module, imp.line, target, imp.kind))
    g.third_party = dict(third)
    g.stdlib = dict(stdlib)
    return g
