# Repository forensics report

- **Repository:** https://github.com/simonw/llm
- **Commit:** `fe283cb9b4d98ab71981181ae9b1fa2dfcaf7ed4`
- **Analyzed:** 2026-10-09T07:33:47+00:00
- **Evidence digest:** `sha256:14a27ee1cf451a87553931578b05ce39`
- **License (heuristic):** Apache-2.0
- **Tool:** repo-forensics 0.1.0, tier 1

> Measurements are facts. Architecture is an inference. Every row below links to an evidence id in `evidence.jsonl`. Status: CONFIRMED / SUPPORTED / INFERRED / UNKNOWN.

## 1. Fingerprint

| Language | Files | Production code lines | Share | Analysis |
|---|---|---|---|---|
| Python | 54 | 13930 | 100.0% | deep |
| Shell | 1 | 0 | 0.0% |  |
| Makefile | 1 | 0 | 0.0% |  |

Build systems: make, pip-requirements, pyproject, setuptools · Package roots: 2 · CI: 4 workflow(s) · File classes: {'config': 11, 'other': 5, 'docs': 37, 'source': 19, 'test': 46}

## 2. Entry points

| Type | Name | Module | Detection | Status | Evidence |
|---|---|---|---|---|---|
| cli | llm | llm.cli | declared console script | CONFIRMED | EV-0025 |
| cli |  | llm.__main__ | __main__.py (python -m) | CONFIRMED | EV-0026 |
| cli |  | llm.cli | decorator `click.group` | CONFIRMED | EV-0027 |
| library-api |  | llm | importable top-level package declared by a package manifest | SUPPORTED | EV-0028 |

Repository shape (INFERRED): **CLI application, library (importable package)** (EV-0046)

## 3. Components (directory-based)

Method: `{'rule': 'directory', 'depth': 2, 'main_package': 'llm', 'main_package_share': 1.0, 'min_file_share_for_own_component': 0.05, 'split_dominant': [], 'synthetic_buckets': ['llm (root modules)']}`

| Component | Modules | LOC | Depth | Depends on | Used by | Tests import it | Signals | Evidence |
|---|---|---|---|---|---|---|---|---|
| llm.cli | 1 | 3817 | 0 | 3 | 2 | 21 | dynamic-code, filesystem, sqlite3 | EV-0041 |
| llm.models | 1 | 3065 | 0 | 2 | 4 | 4 |  | EV-0042 |
| llm.default_plugins | 3 | 2846 | 1 | 3 | 0 | 3 | filesystem, openai, sqlite3 | EV-0043 |
| llm (root modules) | 13 | 2547 | 0 | 2 | 4 | 28 | dynamic-import, plugin-system, sqlite3 | EV-0044 |
| llm.logs | 1 | 1655 | 0 | 2 | 2 | 7 | filesystem | EV-0045 |

_Depth_ = longest dependency chain to a component that depends on nothing internal (0 = bottom layer).

See `architecture.mmd` for the component graph.

## 4. Module graph

19 production modules, 40 edges. Fan-in {'n': 19, 'median': 2.0, 'p90': 6.0, 'p95': 6.0, 'max': 6}; fan-out {'n': 19, 'median': 1.0, 'p90': 6.0, 'p95': 6.2, 'max': 8}.

- Import cycles: **1** (of which at import time: 0)
- Hubs (high fan-in): none
- Orphans: 2

## 5. Computational primitives, storage, boundaries

| Category | Library | Primitive | Usage | Refined | Reachable | Evidence |
|---|---|---|---|---|---|---|
| ai | openai | hosted-llm-inference | CALLED |  | False | EV-0030 |
| boundary | builtins | dynamic-code-execution | CALLED |  | True | EV-0033 |
| boundary | importlib | dynamic-import | CALLED |  | True | EV-0034 |
| boundary | builtins / shutil | filesystem-io | CALLED |  | True | EV-0035 |
| boundary | pluggy / stevedore | plugin-registry | CALLED |  | True | EV-0036 |
| boundary | subprocess / os | subprocess-execution | NON_PRODUCTION_ONLY |  | False | EV-0032 |
| storage | sqlite3 (stdlib) | relational-store | CALLED |  | True | EV-0031 |

Usage levels: DECLARED (manifest) < IMPORTED < CALLED (production code). CENTRAL is decided in the inference step.

## 6. AI fingerprint

Status: **AI_PRESENT** · classification: DEFERRED_TO_INFERENCE

Signature database is finite: NO_AI_SIGNATURE_FOUND is not proof of absence.

## 7. Dependencies

Declared: {'non-production': 7, 'runtime': 15, 'dev': 22, 'build': 1} · Third-party packages imported: 17

- Declared (runtime) but not imported: pyreadline3

## 8. Complexity

552 functions · CC {'n': 552, 'median': 2.0, 'p90': 11.0, 'p95': 18.45, 'max': 119} · functions_cc_gt_10: 58 · functions_cc_gt_20: 23

| Function | File:line | CC | NLOC |
|---|---|---|---|
| prompt | llm/cli.py:685 | 119 | 326 |
| logs_list | llm/cli.py:1883 | 113 | 362 |
| _build_message_parts | llm/models.py:1319 | 63 | 147 |
| register_commands.endpoint | llm/default_plugins/openai_models.py:605 | 60 | 203 |
| execute | llm/default_plugins/openai_models.py:2757 | 47 | 177 |
| execute | llm/default_plugins/openai_models.py:2513 | 43 | 171 |
| tools_list | llm/cli.py:2832 | 38 | 137 |
| execute_tool_calls | llm/models.py:2247 | 37 | 150 |
| chat | llm/cli.py:1247 | 31 | 122 |
| render_model_with_aliases | llm/cli.py:2416 | 30 | 66 |

## 9. Tests (static inventory)

33 test modules, 810 test functions, test/production LOC ratio 1.22, frameworks: pytest, unittest.
Components not imported by any test: none

## 10. Signals (not verdicts)

| Rule | Target | Detail | Severity | Evidence |
|---|---|---|---|---|
| cyclic_dependency | llm, llm.embeddings, llm.logs, llm.models… | 5-module cycle (only via function-level imports) | info | EV-0010 |
| oversized_module | llm.cli | 3817 code lines | info | EV-0011 |
| possibly_unused_dependency | pyreadline3 | declared in runtime scope, never imported | info | EV-0024 |
| component_cycle | llm (root modules), llm.cli, llm.logs, llm.models | 4-component cycle at import time (involves a merged bucket) | info | EV-0039 |
| high_complexity | 22 more functions | CC 16–24 | info | EV-0048 |
| high_complexity | llm.cli::prompt | CC 119, 326 NLOC | warn | EV-0049 |
| high_complexity | llm.cli::logs_list | CC 113, 362 NLOC | warn | EV-0050 |
| high_complexity | llm.models::_build_message_parts | CC 63, 147 NLOC | warn | EV-0051 |
| high_complexity | llm.default_plugins.openai_models::register_commands.endpoint | CC 60, 203 NLOC | warn | EV-0052 |
| high_complexity | llm.default_plugins.openai_models::execute | CC 47, 177 NLOC | warn | EV-0053 |
| high_complexity | llm.default_plugins.openai_models::execute | CC 43, 171 NLOC | warn | EV-0054 |
| high_complexity | llm.cli::tools_list | CC 38, 137 NLOC | warn | EV-0055 |
| high_complexity | llm.models::execute_tool_calls | CC 37, 150 NLOC | warn | EV-0056 |
| high_complexity | llm.cli::chat | CC 31, 122 NLOC | warn | EV-0057 |
| high_complexity | llm.cli::render_model_with_aliases | CC 30, 66 NLOC | warn | EV-0058 |
| high_complexity | llm.default_plugins.openai_models::execute | CC 30, 107 NLOC | warn | EV-0059 |
| high_complexity | llm.default_plugins.openai_models::execute | CC 30, 107 NLOC | warn | EV-0060 |
| high_complexity | llm.default_plugins.openai_models::_build_responses_input | CC 29, 88 NLOC | warn | EV-0061 |
| high_complexity | llm.cli::embed | CC 27, 71 NLOC | warn | EV-0062 |
| high_complexity | llm.cli::embed_multi | CC 24, 74 NLOC | info | EV-0063 |

## 11. Unknowns

- **Which modules are loaded dynamically at runtime?** — importlib/`__import__` calls exist; the static import graph may be missing edges. (EV-0037)
- **Do the tests pass, and what do they cover?** — Tier 0/1 never executes repository code; coverage requires a sandboxed Tier 2 run. (EV-0065)
- **How much code is duplicated?** — Duplication analysis is not implemented in v0.1. (EV-0066)

## 12. Checklist

| Gate | Status | Note |
|---|---|---|
| Repository pinned to commit | done |  |
| Languages identified | done |  |
| Build systems identified | done |  |
| Entry points located | done | Python only |
| Internal modules mapped | done | Python only |
| Dependency inventory generated | done | direct Python deps only; SBOM/transitive in v0.2 |
| Dependency graph generated | done |  |
| Cycles calculated | done |  |
| Fan-in/fan-out calculated | done |  |
| Components inferred | partial | directory-based; responsibilities deferred to inference step |
| External boundaries mapped | done | signature-based |
| Storage mechanisms mapped | done | signature-based |
| Computational primitives identified | done | signature-based; CENTRAL level deferred to inference |
| AI/ML usage identified | partial | presence measured; core vs supporting deferred to inference |
| Complexity measured | done |  |
| Duplication measured | not_done | v0.2 |
| Tests inventoried | done | static only |
| Architecture patterns hypothesized | deferred_to_inference |  |
| Architecture smells identified | done | signals, not verdicts |
| Evidence confidence attached | done |  |
| Counter-evidence recorded | partial | mechanical counter-evidence only; hypotheses must add their own |
| Unknowns explicitly listed | done |  |


Evidence by status: {'CONFIRMED': 59, 'SUPPORTED': 2, 'INFERRED': 2, 'UNKNOWN': 3}
