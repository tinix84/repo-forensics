from repo_forensics.components import OTHER_SUFFIX, ROOT_SUFFIX, component_graph, dependency_depth, plan


def test_flat_package_gets_one_component_per_module():
    mods = {"p": 1, "p.a": 50, "p.b": 5, "p.c": 1}
    mapping, method = plan(mods, {"p"})
    assert mapping["p.a"] == "p.a" and mapping["p.c"] == "p.c"
    assert mapping["p"] == "p" + ROOT_SUFFIX


def test_nested_package_groups_by_subpackage_and_merges_small_files():
    mods = {"p": 1, "p.api.x": 300, "p.api.y": 200, "p.core.z": 400, "p.tiny": 3}
    mapping, method = plan(mods, {"p", "p.api", "p.core"})
    assert mapping["p.api.y"] == "p.api" and mapping["p.core.z"] == "p.core"
    assert mapping["p.tiny"] == "p" + ROOT_SUFFIX
    assert method["synthetic_buckets"] == ["p" + ROOT_SUFFIX]


def test_dominant_component_is_split_with_other_bucket():
    mods = {"p.big.a.m": 400, "p.big.b.m": 300, "p.big.c.m": 4, "p.small.m": 100}
    pk = {"p", "p.big", "p.big.a", "p.big.b", "p.big.c", "p.small"}
    mapping, method = plan(mods, pk, min_file_share=0.05)
    assert method["split_dominant"] == ["p.big"]
    assert mapping["p.big.a.m"] == "p.big.a"
    assert mapping["p.big.c.m"] in ("p.big.c", "p.big" + OTHER_SUFFIX)


def test_dependency_depth_layers():
    mapping = {"ui": "ui", "svc": "svc", "dom": "dom"}
    adj = {"ui": {"svc"}, "svc": {"dom"}, "dom": set()}
    d = dependency_depth(component_graph(mapping, adj))
    assert d == {"dom": 0, "svc": 1, "ui": 2}
