"""FINGERPRINT: languages, file classes, manifests and build systems — mechanically, not guessed."""

from __future__ import annotations

import fnmatch
import tomllib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

# extension -> (language, kind, single-line comment prefix)
EXT_LANG: dict[str, tuple[str, str, str | None]] = {
    ".py": ("Python", "programming", "#"), ".pyi": ("Python", "programming", "#"),
    ".pyx": ("Cython", "programming", "#"),
    ".ipynb": ("Jupyter Notebook", "programming", None),
    ".rs": ("Rust", "programming", "//"),
    ".ts": ("TypeScript", "programming", "//"), ".tsx": ("TypeScript", "programming", "//"),
    ".mts": ("TypeScript", "programming", "//"), ".cts": ("TypeScript", "programming", "//"),
    ".js": ("JavaScript", "programming", "//"), ".jsx": ("JavaScript", "programming", "//"),
    ".mjs": ("JavaScript", "programming", "//"), ".cjs": ("JavaScript", "programming", "//"),
    ".go": ("Go", "programming", "//"),
    ".java": ("Java", "programming", "//"), ".kt": ("Kotlin", "programming", "//"),
    ".scala": ("Scala", "programming", "//"),
    ".c": ("C", "programming", "//"), ".h": ("C/C++ Header", "programming", "//"),
    ".cc": ("C++", "programming", "//"), ".cpp": ("C++", "programming", "//"),
    ".cxx": ("C++", "programming", "//"), ".hpp": ("C/C++ Header", "programming", "//"),
    ".cu": ("CUDA", "programming", "//"),
    ".cs": ("C#", "programming", "//"), ".swift": ("Swift", "programming", "//"),
    ".rb": ("Ruby", "programming", "#"), ".php": ("PHP", "programming", "//"),
    ".m": ("Objective-C/MATLAB", "programming", None), ".jl": ("Julia", "programming", "#"),
    ".r": ("R", "programming", "#"), ".R": ("R", "programming", "#"),
    ".lua": ("Lua", "programming", "--"), ".dart": ("Dart", "programming", "//"),
    ".zig": ("Zig", "programming", "//"),
    ".sh": ("Shell", "programming", "#"), ".bash": ("Shell", "programming", "#"),
    ".ps1": ("PowerShell", "programming", "#"),
    ".sql": ("SQL", "programming", "--"),
    ".vue": ("Vue", "programming", None), ".svelte": ("Svelte", "programming", None),
    ".html": ("HTML", "markup", None), ".css": ("CSS", "markup", None),
    ".scss": ("SCSS", "markup", "//"),
    ".md": ("Markdown", "docs", None), ".rst": ("reStructuredText", "docs", None),
    ".yaml": ("YAML", "data", "#"), ".yml": ("YAML", "data", "#"),
    ".toml": ("TOML", "data", "#"), ".json": ("JSON", "data", None),
    ".ini": ("INI", "data", ";"), ".cfg": ("INI", "data", "#"),
    ".xml": ("XML", "data", None), ".proto": ("Protocol Buffers", "programming", "//"),
}
SPECIAL_NAMES = {"Dockerfile": ("Dockerfile", "programming", "#"),
                 "Makefile": ("Makefile", "programming", "#")}

# manifest file name -> (ecosystem, build_system)
MANIFESTS: dict[str, tuple[str, str]] = {
    "pyproject.toml": ("python", "pyproject"), "setup.py": ("python", "setuptools"),
    "setup.cfg": ("python", "setuptools"), "Pipfile": ("python", "pipenv"),
    "environment.yml": ("python", "conda"), "environment.yaml": ("python", "conda"),
    "tox.ini": ("python", "tox"), "noxfile.py": ("python", "nox"),
    "Cargo.toml": ("rust", "cargo"), "package.json": ("javascript", "npm"),
    "tsconfig.json": ("typescript", "tsc"), "deno.json": ("javascript", "deno"),
    "go.mod": ("go", "go-modules"), "pom.xml": ("java", "maven"),
    "build.gradle": ("java", "gradle"), "build.gradle.kts": ("java", "gradle"),
    "CMakeLists.txt": ("c/c++", "cmake"), "meson.build": ("c/c++", "meson"),
    "Makefile": ("generic", "make"), "Dockerfile": ("container", "docker"),
    "docker-compose.yml": ("container", "docker-compose"),
    "docker-compose.yaml": ("container", "docker-compose"),
    "compose.yaml": ("container", "docker-compose"),
}
LOCKFILE_BUILD = {"poetry.lock": "poetry", "uv.lock": "uv", "pdm.lock": "pdm",
                  "yarn.lock": "yarn", "pnpm-lock.yaml": "pnpm", "Pipfile.lock": "pipenv"}
PACKAGE_MANIFESTS = {"pyproject.toml", "setup.py", "Cargo.toml", "package.json", "go.mod",
                     "pom.xml", "build.gradle", "build.gradle.kts"}


@dataclass
class FileInfo:
    path: str
    language: str | None
    kind: str | None          # programming | markup | docs | data | None
    file_class: str           # source | test | docs | config | generated | vendored | migrations | auxiliary | other
    lines: int = 0
    blank: int = 0
    comment: int = 0
    code: int = 0
    size: int = 0


@dataclass
class Fingerprint:
    files: list[FileInfo]
    languages: dict[str, dict]
    file_classes: dict[str, int]
    manifests: list[dict]
    build_systems: list[str]
    package_roots: list[dict]
    ci: list[str]
    multi_package: bool
    by_path: dict[str, FileInfo] = field(default_factory=dict)


def _lang_for(path: str) -> tuple[str | None, str | None, str | None]:
    p = PurePosixPath(path)
    if p.name in SPECIAL_NAMES:
        return SPECIAL_NAMES[p.name]
    return EXT_LANG.get(p.suffix, EXT_LANG.get(p.suffix.lower(), (None, None, None)))


def classify(path: str, kind: str | None, rules: dict, package_dirs: frozenset[str] = frozenset()) -> str:
    """Classify a file. Directory rules for auxiliary/docs ignore directories that are Python
    packages (contain __init__.py): a package called `demo` or `examples` is product code."""
    p = PurePosixPath(path)
    dirs = set(p.parts[:-1])
    plain_dirs = {d for i, d in enumerate(p.parts[:-1]) if "/".join(p.parts[: i + 1]) not in package_dirs}
    name = p.name
    if dirs & set(rules["vendored_dirs"]):
        return "vendored"
    if any(fnmatch.fnmatch(name, g) for g in rules["generated_globs"]):
        return "generated"
    if dirs & set(rules["migration_dirs"]):
        return "migrations"
    if dirs & set(rules["test_dirs"]) or any(fnmatch.fnmatch(name, g) for g in rules["test_globs"]):
        return "test"
    if plain_dirs & set(rules["auxiliary_dirs"]):
        return "auxiliary"
    if plain_dirs & set(rules["docs_dirs"]) or kind == "docs":
        return "docs"
    if kind == "programming":
        return "source"
    if kind in ("data", "markup"):
        return "config" if kind == "data" else "other"
    return "other"


def count_lines(data: bytes, comment_prefix: str | None) -> tuple[int, int, int, int]:
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    blank = comment = 0
    for ln in lines:
        s = ln.strip()
        if not s:
            blank += 1
        elif comment_prefix and s.startswith(comment_prefix):
            comment += 1
    return len(lines), blank, comment, len(lines) - blank - comment


def fingerprint(root: Path, files: list[str], rules: dict) -> Fingerprint:
    infos: list[FileInfo] = []
    lang_stats: dict[str, dict] = defaultdict(lambda: {"files": 0, "code": 0, "comment": 0,
                                                        "blank": 0, "kind": None,
                                                        "by_class": defaultdict(int)})
    manifests, build_systems, ci = [], set(), []
    package_dirs = frozenset(str(PurePosixPath(f).parent) for f in files if PurePosixPath(f).name == "__init__.py")
    for f in files:
        lang, kind, cprefix = _lang_for(f)
        cls = classify(f, kind, rules, package_dirs)
        fp = root / f
        size = fp.stat().st_size
        info = FileInfo(path=f, language=lang, kind=kind, file_class=cls, size=size)
        if lang and kind != "data" and size <= rules.get("max_parse_bytes", 2_000_000) * 5:
            if lang != "Jupyter Notebook":
                info.lines, info.blank, info.comment, info.code = count_lines(fp.read_bytes(), cprefix)
        infos.append(info)
        if lang:
            st = lang_stats[lang]
            st["kind"] = kind
            st["files"] += 1
            st["code"] += info.code
            st["comment"] += info.comment
            st["blank"] += info.blank
            st["by_class"][cls] += info.code
        name = PurePosixPath(f).name
        if name in MANIFESTS or (name.startswith("requirements") and name.endswith(".txt")):
            eco, bs = MANIFESTS.get(name, ("python", "pip-requirements"))
            if cls not in ("vendored",):
                manifests.append({"path": f, "ecosystem": eco, "build_system": bs})
                build_systems.add(bs)
        if name in LOCKFILE_BUILD and cls != "vendored":
            build_systems.add(LOCKFILE_BUILD[name])
        if f.startswith(".github/workflows/") and f.endswith((".yml", ".yaml")):
            ci.append(f)
        elif f in (".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml", ".circleci/config.yml"):
            ci.append(f)

    # Build backend from pyproject
    for m in manifests:
        if PurePosixPath(m["path"]).name == "pyproject.toml":
            try:
                data = tomllib.loads((root / m["path"]).read_text(encoding="utf-8"))
                backend = (data.get("build-system") or {}).get("build-backend")
                if backend:
                    m["build_backend"] = backend
                    build_systems.add(backend.split(".")[0])
            except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError) as e:
                m["parse_error"] = str(e)[:200]

    # Language shares over production programming code only (source class)
    prod_total = sum(st["by_class"].get("source", 0) for st in lang_stats.values()
                     if st["kind"] == "programming")
    languages = {}
    for lang, st in sorted(lang_stats.items(), key=lambda kv: -kv[1]["code"]):
        src_code = st["by_class"].get("source", 0)
        languages[lang] = {
            "kind": st["kind"], "files": st["files"], "code_lines": st["code"],
            "comment_lines": st["comment"], "blank_lines": st["blank"],
            "source_code_lines": src_code,
            "source_share": round(src_code / prod_total, 4) if prod_total and st["kind"] == "programming" else None,
            "code_lines_by_class": dict(st["by_class"]),
        }

    file_classes: dict[str, int] = defaultdict(int)
    for i in infos:
        file_classes[i.file_class] += 1

    roots = defaultdict(list)
    for m in manifests:
        name = PurePosixPath(m["path"]).name
        if name in PACKAGE_MANIFESTS:
            d = str(PurePosixPath(m["path"]).parent)
            roots["" if d == "." else d].append(name)
    package_roots = [{"dir": d or ".", "manifests": sorted(v)} for d, v in sorted(roots.items())]
    multi = len(package_roots) > 1

    fp_ = Fingerprint(files=infos, languages=languages, file_classes=dict(file_classes),
                      manifests=manifests, build_systems=sorted(build_systems),
                      package_roots=package_roots, ci=sorted(ci), multi_package=multi)
    fp_.by_path = {i.path: i for i in infos}
    return fp_
