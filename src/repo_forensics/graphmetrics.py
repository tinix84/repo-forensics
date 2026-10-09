"""Graph algorithms: fan-in/out, strongly connected components (Tarjan, iterative), reachability."""

from __future__ import annotations

from collections import deque


def fan(adj: dict[str, set[str]]) -> tuple[dict[str, int], dict[str, int]]:
    fan_out = {n: len(v) for n, v in adj.items()}
    fan_in = {n: 0 for n in adj}
    for _, vs in adj.items():
        for v in vs:
            fan_in[v] = fan_in.get(v, 0) + 1
    return fan_in, fan_out


def tarjan_scc(adj: dict[str, set[str]]) -> list[list[str]]:
    """Strongly connected components; iterative to avoid recursion limits."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    result: list[list[str]] = []
    counter = 0
    for root in sorted(adj):
        if root in index:
            continue
        work = [(root, iter(sorted(adj.get(root, ()))))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, it = work[-1]
            advanced = False
            for w in it:
                if w not in index:
                    index[w] = low[w] = counter
                    counter += 1
                    stack.append(w)
                    on_stack.add(w)
                    work.append((w, iter(sorted(adj.get(w, ())))))
                    advanced = True
                    break
                if w in on_stack:
                    low[node] = min(low[node], index[w])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                comp = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp.append(w)
                    if w == node:
                        break
                result.append(sorted(comp))
    return result


def cycles(adj: dict[str, set[str]]) -> list[list[str]]:
    return sorted((c for c in tarjan_scc(adj) if len(c) > 1), key=lambda c: (-len(c), c))


def reachable(adj: dict[str, set[str]], starts: set[str]) -> set[str]:
    seen = set(s for s in starts if s in adj)
    q = deque(seen)
    while q:
        n = q.popleft()
        for m in adj.get(n, ()):
            if m not in seen:
                seen.add(m)
                q.append(m)
    return seen


def percentile(values: list[float], p: float) -> float | None:
    """Linear-interpolation percentile (same convention as numpy's default)."""
    if not values:
        return None
    xs = sorted(values)
    if len(xs) == 1:
        return float(xs[0])
    k = (len(xs) - 1) * p / 100.0
    lo = int(k)
    hi = min(lo + 1, len(xs) - 1)
    return float(xs[lo] + (xs[hi] - xs[lo]) * (k - lo))


def distribution(values: list[float]) -> dict:
    if not values:
        return {"n": 0}
    r = lambda x: round(x, 2)  # noqa: E731
    return {"n": len(values), "median": r(percentile(values, 50)), "p90": r(percentile(values, 90)),
            "p95": r(percentile(values, 95)), "max": max(values)}
