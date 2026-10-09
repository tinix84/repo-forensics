"""Loading of bundled YAML configuration (signatures, thresholds, path rules)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

_DATA = resources.files("repo_forensics") / "data"

SIGNATURE_FILES = ("ai.yaml", "algorithms.yaml", "storage.yaml", "boundaries.yaml")


def normalize_dist(name: str) -> str:
    """PEP 503 normalization of a distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def _load(rel: str) -> Any:
    return yaml.safe_load((_DATA / rel).read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Signature:
    id: str
    library: str
    category: str
    subcategory: str
    primitive: str
    modules: tuple[str, ...]
    distributions: tuple[str, ...]
    refine: tuple[tuple[str, str], ...] = ()
    source_file: str = ""


@dataclass
class Config:
    ignore: dict
    thresholds: dict
    import_aliases: dict[str, str]
    non_import_tools: set[str]
    signatures: list[Signature]
    entrypoint_detectors: list[dict]
    roles: dict[str, str] = field(default_factory=dict)
    patterns: dict[str, str] = field(default_factory=dict)
    extra: dict = field(default_factory=dict)


def _parse_signatures(raw: list[dict], source: str) -> list[Signature]:
    out = []
    for s in raw:
        out.append(
            Signature(
                id=s["id"],
                library=s.get("library", s["id"]),
                category=s["category"],
                subcategory=s.get("subcategory", ""),
                primitive=s["primitive"],
                modules=tuple(s.get("modules", [])),
                distributions=tuple(normalize_dist(d) for d in s.get("distributions", [])),
                refine=tuple((k, v) for k, v in (s.get("refine") or {}).items()),
                source_file=source,
            )
        )
    return out


@lru_cache(maxsize=1)
def load_config(extra_signature_dir: str | None = None) -> Config:
    sigs: list[Signature] = []
    for f in SIGNATURE_FILES:
        sigs += _parse_signatures(_load(f"signatures/{f}") or [], f)
    if extra_signature_dir:
        for p in sorted(Path(extra_signature_dir).glob("*.yaml")):
            sigs += _parse_signatures(yaml.safe_load(p.read_text(encoding="utf-8")) or [], p.name)
    ids = [s.id for s in sigs]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate signature ids: {sorted(dupes)}")
    return Config(
        ignore=_load("ignore.yaml"),
        thresholds=_load("thresholds.yaml"),
        import_aliases={k: normalize_dist(v) for k, v in (_load("import_aliases.yaml") or {}).items()},
        non_import_tools={normalize_dist(x) for x in (_load("non_import_tools.yaml") or [])},
        signatures=sigs,
        entrypoint_detectors=_load("entrypoint_detectors.yaml") or [],
        roles=_load("vocab/roles.yaml") or {},
        patterns=_load("vocab/patterns.yaml") or {},
    )
