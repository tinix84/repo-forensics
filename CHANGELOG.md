# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

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
