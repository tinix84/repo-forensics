import textwrap

from repo_forensics.dependencies import import_to_dist, parse_pyproject, parse_requirements, parse_setup_py, req_name


def test_req_name_variants():
    assert req_name("Scikit_Learn[extra]>=1.0 ; python_version>'3'") == "scikit-learn"
    assert req_name("-r other.txt") is None
    assert req_name("git+https://x/y.git#egg=My.Pkg") == "my-pkg"
    assert req_name("# comment") is None


def test_pyproject_scopes(tmp_path):
    p = tmp_path / "pyproject.toml"
    p.write_text(textwrap.dedent("""
        [project]
        name = "x"
        dependencies = ["a"]
        [project.optional-dependencies]
        extra = ["b"]
        [dependency-groups]
        dev = ["c", {include-group = "other"}]
        [project.scripts]
        x = "x.cli:main"
    """))
    deps, meta = parse_pyproject(p, "pyproject.toml")
    assert {(d.name, d.scope) for d in deps} == {("a", "runtime"), ("b", "optional:extra"), ("c", "dev")}
    assert meta["scripts"] == {"x": "x.cli:main"}


def test_setup_py_is_parsed_never_executed(tmp_path):
    p = tmp_path / "setup.py"
    p.write_text(textwrap.dedent("""
        raise SystemExit("executing setup.py is forbidden")
        from setuptools import setup
        setup(install_requires=["requests>=2"], entry_points={"console_scripts": ["t = t.main:run"]},
              extras_require=compute())
    """))
    deps, meta = parse_setup_py(p, "setup.py")
    assert [d.name for d in deps] == ["requests"]
    assert meta["scripts"] == {"t": "t.main:run"} and meta["non_literal"] == ["extras_require"]


def test_requirements_scope_from_filename(tmp_path):
    p = tmp_path / "requirements-dev.txt"
    p.write_text("pytest\n")
    assert parse_requirements(p, "requirements-dev.txt")[0].scope == "dev"


def test_import_alias_table():
    assert import_to_dist("sklearn.cluster", {"sklearn": "scikit-learn"}) == "scikit-learn"
    assert import_to_dist("google.cloud.storage.blob", {"google.cloud.storage": "google-cloud-storage"}) == "google-cloud-storage"
    assert import_to_dist("Requests", {}) == "requests"
