from repo_forensics.graphmetrics import cycles, fan, percentile, reachable, tarjan_scc


def test_tarjan_finds_cycles_and_ignores_dag_parts():
    adj = {"a": {"b"}, "b": {"c"}, "c": {"a"}, "d": {"a"}, "e": set()}
    assert cycles(adj) == [["a", "b", "c"]]
    assert sorted(map(len, tarjan_scc(adj))) == [1, 1, 3]


def test_tarjan_is_iterative_on_deep_graphs():
    n = 20000
    adj = {str(i): {str(i + 1)} for i in range(n)}
    adj[str(n)] = {"0"}
    assert len(cycles(adj)[0]) == n + 1


def test_fan_and_reachability():
    adj = {"a": {"b", "c"}, "b": {"c"}, "c": set(), "x": set()}
    fi, fo = fan(adj)
    assert fi == {"a": 0, "b": 1, "c": 2, "x": 0} and fo["a"] == 2
    assert reachable(adj, {"a"}) == {"a", "b", "c"}


def test_percentile_matches_linear_interpolation():
    assert percentile([1, 2, 3, 4], 50) == 2.5
    assert percentile([5], 95) == 5.0
    assert percentile([], 50) is None
