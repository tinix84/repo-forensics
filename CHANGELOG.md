# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- `report.html`: self-contained visual report. Evidence status is encoded with technical-drawing line
  types (continuous = fact, dashed = inference, dotted = unknown); component map as inline SVG layered by
  dependency depth; every evidence location links to the exact source line at the pinned commit.
- `repo-forensics render <dir>`: rebuilds the HTML, including `hypotheses.json` only if the bundle validates.
- Corpus layer: `repo-forensics corpus add | compare`. Fact table of triples with global evidence references
  (`owner/repo@sha12#EV-id`); comparisons by shared primitive, by role (same role, different implementation)
  and by architecture pattern with pattern families; weakest-link status for cross-repository statements;
  `compare.html` with a self-contained evidence register.
- Controlled vocabularies `data/vocab/roles.yaml` (19 roles with `implemented_by`) and `patterns.yaml`
  (12 patterns with `parent`); `hypotheses.json` now requires component `roles` and hypothesis `pattern_id`.
- Signatures: hierarchical Leiden / community detection (graspologic, graspologic_native, leidenalg),
  spaCy/NLTK, Azure Blob, Cosmos DB, Azure AI Search, pluggy/stevedore.

### Changed
- `--ref` with an abbreviated SHA now fails with a clear message (shallow fetch needs the full SHA).

### Fixed
- Corpus role table credited every library in a component to each of its roles (e.g. an S3 client as an
  LLM-adapter implementation); implementations are now filtered by the role's `implemented_by`.
- Matrix cells counted declared-only libraries (e.g. `anthropic`) as used.

## [0.1.0] - 2026-10-09

### Added
- CLI `repo-forensics analyze | validate`; Python package with JSON schemas for report, evidence and hypotheses.
- Safe acquisition: single-commit shallow fetch, hooks/submodules/LFS disabled, symlinks as plain files, credentials stripped.
- Fingerprint: languages, LOC by file class, manifests, build systems, CI, package roots.
- Python measurement: AST import graph with module/lazy/TYPE_CHECKING edges, sibling-import resolution,
  fan-in/out, Tarjan SCC cycles (runtime and import-time), hubs, god-module and oversized-module signals, orphans.
- Dependency inventory from pyproject (PEP 621, PEP 735, Poetry), requirements, setup.cfg, setup.py (AST only), Pipfile.
- Entry-point detection: console scripts, entry-point groups, `__main__`, main guards, FastAPI/Flask/Celery/Typer/Click/MCP/… constructors.
- Signature database (AI, algorithms, storage, process boundaries) with DECLARED/IMPORTED/CALLED levels and call-level refinement.
- Directory-based components with dependency depth, component cycles, and automatic splitting of dominant components.
- Complexity distribution via lizard (tier 1); static test inventory.
- Evidence model with content digest; validator enforcing fact/inference separation.
- Claude Code skill (`skills/repo-forensics`) with inference guide and evidence-model reference.
- Worked example: `examples/simonw-llm/`.

### Fixed during validation on real repositories (pre-release)
- Internal modules named like third-party packages (e.g. `flask.*` inside Flask) were matched as signatures.
- Manifests under `examples/`, `tests/`, `docs/` were treated as runtime dependencies.
- `TYPE_CHECKING`-only imports were flagged as undeclared dependencies.
- `ulid` / `python-ulid` style name mismatches; added prefix/suffix heuristics.
- Declaring `numpy` was reported as declaring FFT (submodule signatures no longer use DECLARED).
- Libraries with a CLI were classified only as CLI applications.
- Packages named `demo`/`examples` were classified as auxiliary code.
- Sequential evidence ids allowed stale inferences to validate; added `evidence_digest` binding.
- Self-analysis flagged `_analyze` at cyclomatic complexity 336; refactored into phase methods.
