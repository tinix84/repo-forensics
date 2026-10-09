from repo_forensics.pyparse import parse_file

SRC = b'''
import numpy as np
import os.path
from typing import TYPE_CHECKING
from . import sibling
from ..core import engine as eng
if TYPE_CHECKING:
    from pkg.types import T
def f():
    import json
    np.fft.fft([1])
    eng.run()
    open("x")
    os.environ["KEY_A"]
    os.getenv("KEY_B")
class TestX:
    def test_one(self): pass
def test_two(): pass
if __name__ == "__main__":
    f()
'''


def facts():
    return parse_file("pkg/sub/mod.py", SRC, "pkg.sub.mod", False)


def test_relative_imports_are_resolved_against_the_package():
    mods = {i.module for i in facts().imports}
    assert "pkg.sub" in mods and "pkg.core" in mods


def test_import_kinds():
    kinds = {i.module: i.kind for i in facts().imports}
    assert kinds["pkg.types"] == "type_checking"
    assert kinds["json"] == "lazy"
    assert kinds["numpy"] == "module"


def test_calls_are_qualified_through_aliases():
    q = {c.qualname for c in facts().calls}
    assert {"numpy.fft.fft", "pkg.core.engine.run", "builtins.open", "os.getenv"} <= q


def test_env_vars_main_guard_and_tests():
    f = facts()
    assert {n for n, _ in f.env_vars} == {"KEY_A", "KEY_B"}
    assert f.main_guard_line == 19
    assert f.test_functions == 2


def test_relative_import_beyond_top_is_flagged_not_crashing():
    f = parse_file("a.py", b"from ... import x\n", "a", False)
    assert f.imports[0].unresolved


def test_syntax_error_is_recorded():
    f = parse_file("py2.py", b"print 'hello'\n", "py2", False)
    assert f.syntax_error and not f.imports


def test_init_package_relative_import():
    f = parse_file("pkg/__init__.py", b"from .core import x\n", "pkg", True)
    assert f.imports[0].module == "pkg.core"
