# repo-forensics

**Evidence-first reverse engineering of software repositories.**
Given a repository at a pinned commit, `repo-forensics` establishes what can be shown from
evidence about its architecture, entry points, dependencies, computational primitives,
AI usage and complexity, and states explicitly what it cannot know.

> **Measurements are facts. Architecture is an inference.**
> The CLI measures. A language model (via the bundled Claude Code skill) infers.
> A validator keeps the two apart.

[![CI](https://github.com/tinix84/repo-forensics/actions/workflows/ci.yml/badge.svg)](https://github.com/tinix84/repo-forensics/actions/workflows/ci.yml)
License: MIT · Status: v0.1 (alpha) · Deep analysis: Python

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

## Quick start

```bash
pip install "repo-forensics[complexity] @ git+https://github.com/tinix84/repo-forensics"

repo-forensics analyze pallets/flask --out analysis/flask          # GitHub shorthand
repo-forensics analyze https://github.com/simonw/llm --ref fe283cb9 --out analysis/llm --keep-clone
repo-forensics analyze ./my-local-repo --out analysis/mine
repo-forensics validate analysis/llm
```

Options: `--tier 0|1` (0 = parsing only; 1 = also lizard, default), `--component-depth 1|2`,
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

## Output bundle

```
analysis/<name>/
├── report.json            # stable interface for downstream tools (JSON Schema 2020-12)
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
- **No duplication analysis, no SBOM/transitive dependencies, no test execution** yet.

## Roadmap

| Version | Scope |
|---|---|
| v0.2 | Adapter layer: Semgrep, Syft SBOM, PMD CPD duplication, all writing the same evidence schema |
| v0.3 | Second ecosystem (TypeScript or Rust) via tree-sitter, to test language-neutral normalization |
| v0.4 | Tier 2: build-aware analysis (mypy, tests) inside a disposable, network-less container |
| later | Adversarial-reviewer skill consuming `report.json` + `hypotheses.json`; evidence graph export |

## Security model

The analyzed repository is treated as untrusted input. See [SECURITY.md](SECURITY.md).

## References

- R. Tarjan, "Depth-first search and linear graph algorithms," *SIAM J. Computing* 1(2), 1972, [doi:10.1137/0201010](https://doi.org/10.1137/0201010). Used for cycle detection (iterative implementation).
- T. J. McCabe, "A Complexity Measure," *IEEE TSE* SE-2(4), 1976, [doi:10.1109/TSE.1976.233837](https://doi.org/10.1109/TSE.1976.233837). Defines cyclomatic complexity.
- lizard, the complexity analyzer used at tier 1: <https://github.com/terryyin/lizard>
- Python `ast` (parsing without execution): <https://docs.python.org/3/library/ast.html>; `sys.stdlib_module_names`: <https://docs.python.org/3/library/sys.html#sys.stdlib_module_names>
- PEP 503 (name normalization) <https://peps.python.org/pep-0503/>, PEP 621 (project metadata) <https://peps.python.org/pep-0621/>, PEP 735 (dependency groups) <https://peps.python.org/pep-0735/>
- JSON Schema 2020-12: <https://json-schema.org/draft/2020-12>; Mermaid: <https://mermaid.js.org/>

## License

MIT, see [LICENSE](LICENSE).
