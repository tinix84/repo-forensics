# repo-forensics

**Evidence-first reverse engineering of software repositories.**
Given a repository at a pinned commit, `repo-forensics` establishes what can be shown from
evidence about its architecture, entry points, dependencies, computational primitives,
AI usage and complexity, and states explicitly what it cannot know.

> **Measurements are facts. Architecture is an inference.**
> The CLI measures. A language model (via the bundled Claude Code skill) infers.
> A validator keeps the two apart.

License: MIT · Status: v0.2 (alpha) · Deep analysis: Python

---

## Why

Asking an LLM "how is this repo architected?" produces fluent answers with no way to tell
observation from guesswork. This project splits the job:

| Layer | Produced by | Example | Status |
|---|---|---|---|
| Measurement | deterministic code | `src/api` imports `src/core` 27 times; `faiss.IndexHNSWFlat` is called at `index.py:82` | CONFIRMED |
| Interpretation | LLM, constrained by schema | "API → core layering", with confidence and counter-evidence | INFERRED / SUPPORTED |
| Gaps | both | "model is selected by `EMBED_MODEL` at runtime" | UNKNOWN |

Every finding is an evidence item with an id, status, confidence, file/line locations and
counter-evidence. The validator rejects inferences that cite missing evidence, record no
counter-evidence, upgrade themselves to `CONFIRMED`, or were derived from a different
evidence set (content digest).

## Pipeline

```
ACQUIRE ─► FINGERPRINT ─► MEASURE ─► DECOMPOSE ─► INFER ─► REPORT
 (CLI)       (CLI)         (CLI)       (CLI)       (LLM)    (both, validated)
```

| Phase | What it does |
|---|---|
| Acquire | Shallow fetch of one commit; hooks, submodules and LFS disabled; symlinks checked out as plain files; credentials stripped from recorded URLs; SHA pinned |
| Fingerprint | Languages and LOC by file class (source/test/docs/examples/vendored/generated), manifests, build systems, CI, package roots |
| Measure | Python AST import graph (module / lazy / `TYPE_CHECKING` edges), fan-in/out, cycles (Tarjan), hubs, orphans; declared vs imported dependencies; entry points; ~80 library signatures graded DECLARED → IMPORTED → CALLED; env-var configuration; complexity (lizard); static test inventory |
| Decompose | Directory-based components, component graph, dependency depth, import-time vs lazy component cycles; dominant components are split automatically |
| Infer | Component responsibilities, architecture hypotheses with counter-evidence, primitive roles (CENTRAL/SUPPORTING/INCIDENTAL), AI classification, written to `hypotheses.json` |

## Tiers: static, analyzers, dynamic

| Tier | Runs | Executes the repo's code? |
|---|---|---|
| 0 | AST parsing, manifests, graph metrics | no |
| 1 (default) | + lizard, ruff (SARIF), vulture, bandit | no |
| 2 (`--tier 2`) | + wheel-only install, entry-point probes, tests under coverage, runtime call graph (PEP 669 `sys.monitoring`), deptry and mypy in the installed environment | **yes**, in a process-level sandbox (see SECURITY.md) |

Tool findings are facts about tools, not about code; a fusion step turns them into calibrated claims
using independent methods. On simonw/llm, vulture reports 99 "unused" functions or methods (60 %
confidence); in the Tier 2 run 83 of them executed, so those claims are refuted with run-scoped
evidence; plugin modules with no static importer were observed loaded by the CLI through pluggy.
Agreement only counts between independent methods, and one execution can refute "never used"
while non-execution can never confirm it.

## Quick start

```bash
pip install "repo-forensics[tier1] @ git+https://github.com/tinix84/repo-forensics"

repo-forensics analyze pallets/flask --out analysis/flask          # GitHub shorthand
repo-forensics analyze https://github.com/simonw/llm --ref fe283cb9 --out analysis/llm --keep-clone
repo-forensics analyze ./my-local-repo --out analysis/mine
repo-forensics validate analysis/llm
repo-forensics render analysis/llm      # rebuild report.html including the validated inference layer
```

Options: `--tier 0|1|2` (see Tiers), `--component-depth 1|2`,
`--signatures DIR` (extra signature YAML), `--keep-clone`, `--workdir`.

### Claude Code skill

```bash
cp -r skills/repo-forensics ~/.claude/skills/          # user-level
# or: cp -r skills/repo-forensics <project>/.claude/skills/
```

Then ask Claude Code: *"Tear down github.com/simonw/llm: how is it architected and how central is OpenAI?"*
The skill runs the CLI, reads the code it needs, writes `hypotheses.json`, and iterates until
`repo-forensics validate` passes. A worked, validated example is in
[`examples/simonw-llm/`](examples/simonw-llm/).

## Comparing repositories

A single report cannot show what tools have in common, so bundles can be collected into a
corpus and compared on three shared vocabularies:

| Common ground | Based on | Status |
|---|---|---|
| Shared primitives (e.g. 3/3 call hosted LLM inference; 2/3 use ANN search via different libraries) | signature database | fact |
| Same role, different implementation (e.g. retrieval via LanceDB vs Qdrant) | `roles.yaml` + measured signals filtered by role | inference |
| Architecture patterns and families (graph-rag and rag meet in the rag family) | `patterns.yaml` | inference |

```bash
repo-forensics corpus add analysis/llm analysis/graphrag analysis/private-gpt --corpus corpus
repo-forensics corpus compare --corpus corpus     # facts.jsonl, compare.json, compare.html
```

Facts are triples with global evidence references (`owner/repo@sha12#EV-0042`); a statement that
spans repositories takes the weakest status of its inputs. Worked example:
[`examples/corpus-ai-tools/`](examples/corpus-ai-tools/) (simonw/llm, microsoft/graphrag, zylon-ai/private-gpt).

## Output bundle

```
analysis/<name>/
├── report.json            # stable interface for downstream tools (JSON Schema 2020-12)
├── report.html            # self-contained visual report (facts solid, inferences dashed, unknowns dotted)
├── report.md              # human-readable report
├── evidence.jsonl         # one evidence item per line
├── hypotheses.json        # inference layer (written by the skill, validated)
├── architecture.mmd       # component graph (Mermaid)
├── dependency-graph.json  # every module and import edge
└── metrics/               # languages.json, complexity.json (per function)
```

Schemas: [`src/repo_forensics/schemas/`](src/repo_forensics/schemas/).
Method details: [`skills/repo-forensics/references/evidence-model.md`](skills/repo-forensics/references/evidence-model.md).

## Validation so far

Run against Flask, simonw/llm and zylon-ai/private-gpt during development. Bugs found and
fixed by that validation are listed in the [CHANGELOG](CHANGELOG.md). Running the tool on its own code
found a function with cyclomatic complexity 336, since refactored (max 38). 42 tests
run against a synthetic repository that plants each pattern the analyzer must detect.

## Known limitations (v0.1)

- **Python only** for deep analysis; other languages are fingerprinted and listed as unknowns.
- **No type inference**: method calls on objects (`client.chat.create()`) are invisible;
  constructors (`openai.OpenAI()`) are not. `CALLED` under-counts.
- **Dynamic loading** (plugins, importlib) adds runtime edges the static graph lacks; this
  is reported as an explicit unknown.
- **Signature database is finite**: absence of a signature is not absence of a technique.
- **Components are directory-based**; merged buckets are flagged `synthetic`.
- **Tier 2 is process-level isolation only** (no container, network available): demo-grade.
- **Dynamic evidence covers what the probes and tests exercise**; untested paths stay unknown.
- **No duplication analysis, no SBOM, no vulnerability scan** yet.

## Roadmap

| Version | Scope |
|---|---|
| v0.2 | Released: HTML report, corpus comparison, Tier 1 analyzers, Tier 2 dynamic Python, fusion |
| v0.3 | Container runner for Tier 2, import-linter contracts from hypotheses, Semgrep/Syft/duplication adapters |
| v0.4 | Second ecosystem (TypeScript or Rust) through the same adapter contract |
| later | Adversarial-reviewer skill consuming `report.json` + `hypotheses.json`; evidence graph export |

## Security model

The analyzed repository is treated as untrusted input. See [SECURITY.md](SECURITY.md).

## References

- R. Tarjan, "Depth-first search and linear graph algorithms," *SIAM J. Computing* 1(2), 1972, [doi:10.1137/0201010](https://doi.org/10.1137/0201010). Used for cycle detection (iterative implementation).
- T. J. McCabe, "A Complexity Measure," *IEEE TSE* SE-2(4), 1976, [doi:10.1109/TSE.1976.233837](https://doi.org/10.1109/TSE.1976.233837). Defines cyclomatic complexity.
- lizard, the complexity analyzer used at tier 1: <https://github.com/terryyin/lizard>
- ruff <https://github.com/astral-sh/ruff>, vulture <https://github.com/jendrikseipp/vulture>, bandit <https://github.com/PyCQA/bandit>, deptry <https://github.com/osprey-oss/deptry>, mypy <https://github.com/python/mypy>, coverage.py <https://github.com/nedbat/coveragepy>
- SARIF 2.1.0 (OASIS): <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>
- PEP 669, low-impact monitoring (`sys.monitoring`): <https://peps.python.org/pep-0669/>
- Python `ast` (parsing without execution): <https://docs.python.org/3/library/ast.html>; `sys.stdlib_module_names`: <https://docs.python.org/3/library/sys.html#sys.stdlib_module_names>
- PEP 503 (name normalization) <https://peps.python.org/pep-0503/>, PEP 621 (project metadata) <https://peps.python.org/pep-0621/>, PEP 735 (dependency groups) <https://peps.python.org/pep-0735/>
- JSON Schema 2020-12: <https://json-schema.org/draft/2020-12>; Mermaid: <https://mermaid.js.org/>

## License

MIT, see [LICENSE](LICENSE).
