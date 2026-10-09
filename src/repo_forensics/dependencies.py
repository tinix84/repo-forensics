"""Dependency inventory from Python manifests (parsed, never executed)."""

from __future__ import annotations

import ast
import configparser
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .config import normalize_dist

_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


@dataclass
class Declared:
    name: str            # normalized distribution name
    raw: str             # requirement string as written
    scope: str           # runtime | optional:<group> | dev | build
    manifest: str
    line: int | None = None


def req_name(req: str) -> str | None:
    req = req.strip()
    if not req or req.startswith(("#", "-", "git+", "http://", "https://", "file:", ".")):
        m = re.search(r"#egg=([A-Za-z0-9._-]+)", req)
        return normalize_dist(m.group(1)) if m else None
    m = _REQ_NAME.match(req)
    return normalize_dist(m.group(1)) if m else None


def _from_list(items, scope, manifest, out):
    for r in items or []:
        if isinstance(r, str):
            n = req_name(r)
            if n:
                out.append(Declared(n, r, scope, manifest))
        elif isinstance(r, dict) and "include-group" in r:  # PEP 735 include
            continue


def parse_pyproject(path: Path, rel: str) -> tuple[list[Declared], dict]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    out: list[Declared] = []
    proj = data.get("project") or {}
    _from_list(proj.get("dependencies"), "runtime", rel, out)
    for grp, items in (proj.get("optional-dependencies") or {}).items():
        _from_list(items, f"optional:{grp}", rel, out)
    for items in (data.get("dependency-groups") or {}).values():
        _from_list(items, "dev", rel, out)
    _from_list((data.get("build-system") or {}).get("requires"), "build", rel, out)
    poetry = (data.get("tool") or {}).get("poetry") or {}
    for name, spec in (poetry.get("dependencies") or {}).items():
        if name.lower() != "python":
            scope = "optional:extras" if isinstance(spec, dict) and spec.get("optional") else "runtime"
            out.append(Declared(normalize_dist(name), f"{name} {spec}", scope, rel))
    for name in (poetry.get("dev-dependencies") or {}):
        out.append(Declared(normalize_dist(name), name, "dev", rel))
    for grp, g in (poetry.get("group") or {}).items():
        for name in (g.get("dependencies") or {}):
            scope = "dev" if grp in ("dev", "test", "docs", "lint") else f"optional:{grp}"
            out.append(Declared(normalize_dist(name), name, scope, rel))
    meta = {
        "name": proj.get("name") or poetry.get("name"),
        "scripts": dict(proj.get("scripts") or {}) | dict(poetry.get("scripts") or {}),
        "gui_scripts": dict(proj.get("gui-scripts") or {}),
        "entry_points": {k: dict(v) for k, v in (proj.get("entry-points") or {}).items()},
        "license": proj.get("license") if isinstance(proj.get("license"), str)
        else (proj.get("license") or {}).get("text") if isinstance(proj.get("license"), dict) else None,
        "requires_python": proj.get("requires-python"),
    }
    return out, meta


def parse_requirements(path: Path, rel: str) -> list[Declared]:
    name = PurePosixPath(rel).name.lower()
    scope = "dev" if any(t in name for t in ("dev", "test", "lint", "doc", "ci")) else "runtime"
    out = []
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = line.split(" #", 1)[0].strip()
        n = req_name(line)
        if n:
            out.append(Declared(n, line, scope, rel, i))
    return out


def parse_setup_cfg(path: Path, rel: str) -> tuple[list[Declared], dict]:
    cp = configparser.ConfigParser(interpolation=None)
    cp.read_string(path.read_text(encoding="utf-8", errors="replace"))
    out: list[Declared] = []
    meta: dict = {"scripts": {}}
    if cp.has_option("options", "install_requires"):
        _from_list(cp.get("options", "install_requires").splitlines(), "runtime", rel, out)
    if cp.has_section("options.extras_require"):
        for grp, val in cp.items("options.extras_require"):
            _from_list(val.splitlines(), f"optional:{grp}", rel, out)
    if cp.has_section("options.entry_points") and cp.has_option("options.entry_points", "console_scripts"):
        for ln in cp.get("options.entry_points", "console_scripts").splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                meta["scripts"][k.strip()] = v.strip()
    return out, meta


def parse_setup_py(path: Path, rel: str) -> tuple[list[Declared], dict]:
    """Extract literal install_requires / entry_points from setup() via AST. Never executed."""
    out: list[Declared] = []
    meta: dict = {"scripts": {}, "non_literal": []}
    try:
        tree = ast.parse(path.read_bytes())
    except SyntaxError:
        return out, meta
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None)) == "setup":
            for kw in node.keywords:
                try:
                    val = ast.literal_eval(kw.value)
                except (ValueError, SyntaxError, TypeError):
                    if kw.arg in ("install_requires", "extras_require", "entry_points"):
                        meta["non_literal"].append(kw.arg)
                    continue
                if kw.arg == "install_requires":
                    _from_list(val, "runtime", rel, out)
                elif kw.arg == "extras_require" and isinstance(val, dict):
                    for g, items in val.items():
                        _from_list(items, f"optional:{g}", rel, out)
                elif kw.arg == "entry_points" and isinstance(val, dict):
                    for ln in val.get("console_scripts", []) or []:
                        if "=" in ln:
                            k, v = ln.split("=", 1)
                            meta["scripts"][k.strip()] = v.strip()
    return out, meta


def parse_pipfile(path: Path, rel: str) -> list[Declared]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    out = [Declared(normalize_dist(n), n, "runtime", rel) for n in (data.get("packages") or {})]
    out += [Declared(normalize_dist(n), n, "dev", rel) for n in (data.get("dev-packages") or {})]
    return out


def collect(root: Path, manifests: list[dict]) -> tuple[list[Declared], list[dict], list[dict]]:
    """Return (declared deps, python package metadata per manifest, parse errors)."""
    declared: list[Declared] = []
    metas: list[dict] = []
    errors: list[dict] = []
    for m in manifests:
        rel = m["path"]
        name = PurePosixPath(rel).name
        p = root / rel
        try:
            if name == "pyproject.toml":
                d, meta = parse_pyproject(p, rel)
                declared += d
                metas.append({"manifest": rel, **meta})
            elif name.startswith("requirements") and name.endswith(".txt"):
                declared += parse_requirements(p, rel)
            elif name == "setup.cfg":
                d, meta = parse_setup_cfg(p, rel)
                declared += d
                metas.append({"manifest": rel, **meta})
            elif name == "setup.py":
                d, meta = parse_setup_py(p, rel)
                declared += d
                metas.append({"manifest": rel, **meta})
            elif name == "Pipfile":
                declared += parse_pipfile(p, rel)
        except (tomllib.TOMLDecodeError, configparser.Error, OSError, UnicodeDecodeError) as e:
            errors.append({"manifest": rel, "error": f"{type(e).__name__}: {e}"[:300]})
    return declared, metas, errors


def import_to_dist(full_module: str, aliases: dict[str, str]) -> str:
    """Map an imported module path to its most likely distribution name."""
    parts = full_module.split(".")
    for i in range(len(parts), 0, -1):
        k = ".".join(parts[:i])
        if k in aliases:
            return aliases[k]
    return normalize_dist(parts[0])
