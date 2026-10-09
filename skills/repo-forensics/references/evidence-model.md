# Evidence model

## Statuses

| Status | Meaning | Default confidence | Who may emit it |
|---|---|---|---|
| CONFIRMED | Direct observation in source/config (an import at a line, a manifest entry) | 1.0 | CLI only |
| SUPPORTED | Multiple indirect observations or a strong heuristic (license text match, `argparse` ⇒ CLI) | 0.8 | CLI, LLM |
| INFERRED | Most plausible interpretation (directory = component, repo shape) | 0.6 | CLI, LLM |
| UNKNOWN | Insufficient evidence; confidence is `null` by schema | — | CLI, LLM |

The LLM inference layer may not use `CONFIRMED` and is capped at confidence 0.95.

## Usage levels (signals)

`DECLARED` (in a production manifest) < `IMPORTED` (production code imports it) <
`CALLED` (production code calls a qualified name from it) < `CENTRAL` (on the main product
path — decided in `hypotheses.json`, only for `CALLED`). `NON_PRODUCTION_ONLY` = seen only in
tests, examples, docs or scripts outside the package.

Submodule signatures (e.g. `numpy.fft`, `sklearn.cluster`) are never `DECLARED`: declaring
numpy says nothing about FFT.

## Known blind spots (state them when relevant)

- **Method calls on objects are invisible.** `client.chat.completions.create()` is not
  resolved; the constructor `openai.OpenAI()` is. `CALLED` therefore under-counts.
- **Dynamic loading** (importlib, plugins, entry-point groups) adds edges the static graph lacks;
  a `dynamic-import` signal raises an explicit unknown. Low `reachable_from_entrypoint` for a
  plugin-loaded module is expected, not a contradiction.
- **Alias tracking is file-global**, not scope-aware.
- **Signature database is finite.** `NO_AI_SIGNATURE_FOUND` ≠ no AI.
- **Complexity** is lizard's cyclomatic count (McCabe), which also counts boolean operators
  and comprehension conditions; compare within a repo rather than across languages.
- **Component = directory grouping.** Merged buckets (`(root modules)`, `(other)`) are marked
  `synthetic`; cycles through them may be grouping artefacts (recorded as counter-evidence).

## Graph facts

- Edges are `module` (import time), `lazy` (inside a function) or `type_checking`
  (under `if TYPE_CHECKING:`). Cycles exclude `type_checking`; `import_time_cycles` also
  exclude `lazy`. A cycle closed only by lazy imports is often a deliberate cycle breaker.
- `dependency_depth`: longest chain to a component with no internal dependencies
  (0 = bottom). Components in one cycle share a depth.
- Hubs = fan-in above P95 (and ≥ 8): candidate core abstractions. God-module candidates =
  above P95 in fan-in, fan-out and size simultaneously, with absolute floors.

## Binding inferences to evidence

`report.json` carries `evidence_digest` (SHA-256 over the canonical evidence lines).
`hypotheses.json` must copy it. Evidence ids (`EV-0042`) are sequential within one run, so
the same id can name a different fact after a tool upgrade or signature change; the digest
makes that drift detectable instead of silent. The validator also recomputes the digest
from `evidence.jsonl`, which detects edited or mixed bundles.

## Bundle layout

```
analysis/<name>/
├── report.json            # interface for downstream skills (schema: report.schema.json)
├── report.md              # human-readable
├── evidence.jsonl         # one evidence item per line (schema: evidence.schema.json)
├── hypotheses.json        # written by the LLM (schema: hypotheses.schema.json)
├── architecture.mmd       # component graph (Mermaid)
├── dependency-graph.json  # module nodes and every import edge
└── metrics/{languages,complexity}.json
```
