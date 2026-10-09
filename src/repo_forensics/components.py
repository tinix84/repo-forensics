"""DECOMPOSE: collapse modules into directory-based components and compute component-level graph facts.

The grouping rule is mechanical (directories), which is why membership is a fact.
Whether a directory is a coherent architectural unit is an inference, recorded as such.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from .graphmetrics import tarjan_scc

ROOT_SUFFIX = " (root modules)"
SCRIPTS = "(top-level scripts)"


def plan(prod_modules: dict[str, int], packages: set[str], depth: int | None = None,
         min_file_share: float = 0.05, max_components: int = 25) -> tuple[dict[str, str], dict]:
    """Return (module -> component, method description).

    prod_modules: module -> code LOC. packages: modules that are packages (__init__).
    """
    total = sum(prod_modules.values()) or 1
    top_loc: Counter = Counter()
    for m, n in prod_modules.items():
        top_loc[m.split(".")[0]] += n
    main, main_loc = (top_loc.most_common(1)[0] if top_loc else (None, 0))
    is_pkg_dir = lambda name: name in packages or any(x.startswith(name + ".") for x in prod_modules)  # noqa: E731
    if depth is None:
        depth = 2 if (main and main_loc / total >= 0.7 and is_pkg_dir(main)) else 1
    has_subpackages = bool(main) and (
        any(m.startswith(f"{main}.") and m.count(".") >= 2 for m in prod_modules)
        or any(p.startswith(f"{main}.") for p in packages))
    if not has_subpackages:
        min_file_share = 0.0   # flat package: every module is its own component
    mapping: dict[str, str] = {}
    for m in prod_modules:
        parts = m.split(".")
        top = parts[0]
        if not is_pkg_dir(top):
            mapping[m] = SCRIPTS
            continue
        if depth >= 2 and top == main:
            if len(parts) >= 2:
                second = f"{top}.{parts[1]}"
                if is_pkg_dir(second):
                    mapping[m] = second
                else:
                    loc = prod_modules.get(second, 0)
                    mapping[m] = second if loc / total >= min_file_share else top + ROOT_SUFFIX
            else:
                mapping[m] = top + ROOT_SUFFIX
        else:
            mapping[m] = top
    # Guard against over-fragmentation
    if len(set(mapping.values())) > max_components and depth >= 2:
        return plan(prod_modules, packages, depth=1)
    split = _split_dominant(mapping, prod_modules, is_pkg_dir, total, max_components)
    method = {
        "rule": "directory",
        "depth": depth,
        "main_package": main,
        "main_package_share": round(main_loc / total, 4) if main else None,
        "min_file_share_for_own_component": min_file_share,
        "split_dominant": split,
        "synthetic_buckets": sorted({c for c in mapping.values()
                                     if c.endswith((ROOT_SUFFIX, OTHER_SUFFIX)) or c == SCRIPTS}),
    }
    return mapping, method


OTHER_SUFFIX = " (other)"


def _split_dominant(mapping: dict[str, str], prod_modules: dict[str, int], is_pkg_dir, total: int,
                    max_components: int, share: float = 0.4, min_child_share: float = 0.01) -> list[str]:
    """Split, one level deeper, any component holding more than `share` of production LOC.

    Children are kept largest-first within the component budget; the remainder is merged into a
    synthetic "<component> (other)" bucket so the graph stays readable.
    """
    loc_by: Counter = Counter()
    for m, c in mapping.items():
        loc_by[c] += prod_modules[m]
    split = []
    for comp, n in sorted(loc_by.items(), key=lambda kv: -kv[1]):
        if n / total <= share or comp.endswith((ROOT_SUFFIX, OTHER_SUFFIX)) or comp == SCRIPTS:
            continue
        depth = comp.count(".") + 1
        child_of: dict[str, str] = {}
        child_loc: Counter = Counter()
        for m, c in mapping.items():
            if c != comp:
                continue
            parts = m.split(".")
            child = ".".join(parts[: depth + 1]) if len(parts) > depth else None
            child = child if child and is_pkg_dir(child) else comp + ROOT_SUFFIX
            child_of[m] = child
            child_loc[child] += prod_modules[m]
        budget = max_components - (len(set(mapping.values())) - 1) - 1
        keep = [c for c, k in child_loc.most_common() if k / total >= min_child_share][: max(budget, 0)]
        if len(keep) < 2:
            continue
        for m, child in child_of.items():
            mapping[m] = child if child in keep else comp + OTHER_SUFFIX
        split.append(comp)
    return split


def component_graph(mapping: dict[str, str], adj: dict[str, set[str]]) -> dict[str, Counter]:
    cg: dict[str, Counter] = defaultdict(Counter)
    for src, dsts in adj.items():
        cs = mapping.get(src)
        if cs is None:
            continue
        cg.setdefault(cs, Counter())
        for d in dsts:
            cd = mapping.get(d)
            if cd is not None and cd != cs:
                cg[cs][cd] += 1
    for c in set(mapping.values()):
        cg.setdefault(c, Counter())
    return cg


def dependency_depth(cg: dict[str, Counter]) -> dict[str, int]:
    """Longest path to a sink in the condensation DAG (0 = depends on no other component).

    Components in the same cycle share a depth. Higher depth = closer to the 'top' of a layering.
    """
    adj = {c: set(v) for c, v in cg.items()}
    sccs = tarjan_scc(adj)
    comp_of = {n: i for i, s in enumerate(sccs) for n in s}
    dag: dict[int, set[int]] = defaultdict(set)
    for c, vs in adj.items():
        for v in vs:
            if comp_of[c] != comp_of[v]:
                dag[comp_of[c]].add(comp_of[v])
    memo: dict[int, int] = {}

    def depth(i: int) -> int:
        stack = [(i, False)]
        while stack:
            node, done = stack.pop()
            if node in memo:
                continue
            if done:
                memo[node] = 1 + max((memo[j] for j in dag[node]), default=-1)
                continue
            stack.append((node, True))
            for j in dag[node]:
                if j not in memo:
                    stack.append((j, False))
        return memo[i]

    return {c: depth(comp_of[c]) for c in adj}
