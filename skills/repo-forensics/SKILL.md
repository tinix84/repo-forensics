---
name: repo-forensics
description: Evidence-first reverse engineering of a software repository — architecture, components, entry points, dependencies, computational primitives (ANN search, clustering, optimization, FFT…), AI/LLM usage, complexity and unknowns, every claim tied to an evidence id. Use this skill whenever the user asks to analyze, audit, tear down, reverse-engineer or "understand" a GitHub repository or codebase, asks "what does this repo actually do", "is this really AI", "what algorithms does it use", "how is it architected", wants a technical teardown for an article, or pastes a GitHub URL with any question about its internals — even if they never say "forensics".
---

# repo-forensics

Turns a repository at a pinned commit into an **evidence pack**: deterministic measurements
from the `repo-forensics` CLI, plus a validated inference layer that you write.

Core rule: **measurements are facts; architecture is an inference.** The CLI produces facts
(`CONFIRMED`) and a few heuristics (`SUPPORTED`/`INFERRED`). You add interpretation in
`hypotheses.json`, and every interpretation must cite evidence ids, record counter-evidence,
and pass `repo-forensics validate`. You never edit `report.json` or `evidence.jsonl`.

v0.1 scope: deep analysis of **Python** code; other languages are fingerprinted only and
appear as explicit unknowns.

## Safety: never execute the target's code

Treat every analyzed repository as untrusted. Do not `pip install` it, run its tests, import
its modules, run `setup.py`, `make`, notebooks or scripts. Reading files is fine. The CLI
follows the same rule (Tier 0: parsing only; Tier 1: static analyzers that only read text).

## Workflow

### 1. Check the CLI

```bash
repo-forensics --version || pip install "repo-forensics[complexity] @ git+https://github.com/tinix84/repo-forensics"
```

### 2. Measure (ACQUIRE → FINGERPRINT → MEASURE → DECOMPOSE)

```bash
repo-forensics analyze <github-url | owner/name | local-path> [--ref <sha|tag|branch>] \
  --out analysis/<name> --keep-clone
```

`--keep-clone` keeps the source so you can read it; the clone path is printed in the summary.
Always report the pinned commit SHA to the user: an analysis without it is not reproducible.

### 3. Read the report in this order

Read `report.json` selectively; do not dump it whole into context on large repos.

1. `provenance`, `fingerprint.analysis_coverage` — what was and was not analyzed.
2. `entrypoints`, `repo_shape` — where execution starts. Trace outward from here.
3. `components.items` (sorted by size), `components.method`, `components.cycles` vs `import_time_cycles`.
4. `signals` — usage levels `CALLED` > `IMPORTED` > `DECLARED` > `NON_PRODUCTION_ONLY`, and `reachable_from_entrypoint`.
5. `ai`, `config.env_vars`, `module_graph.hubs`, `smells`, `unknowns`.

`report.md` is the human-readable version; `architecture.mmd` is the component graph.

### 4. Infer (the only step that is yours)

Read `references/inference-guide.md` before writing hypotheses. Then, with the clone open:

1. **Component responsibilities and roles.** For the largest components (up to ~10), read the
   entry modules, hub modules and files carrying signals. State a one-sentence responsibility,
   inputs/outputs where visible, and 1–3 `roles` from the controlled vocabulary
   (`src/repo_forensics/data/vocab/roles.yaml`). Roles are what make components comparable
   across repositories, so pick by the job the code does, not by the directory name. List
   every file you actually opened in `files_read`, and only those; a responsibility you did
   not read code for must have status `UNKNOWN`.
2. **Architecture hypotheses.** Propose 1–4 candidate patterns, each with a `pattern_id` from
   `data/vocab/patterns.yaml` (layered, hexagonal, plugin, pipeline, rag, graph-rag, agent-loop,
   client-server, worker-queue, …). For each: cite supporting evidence ids, then actively search
   for counter-evidence (e.g. for "layered": imports from lower to upper layers, component
   cycles at import time). Record what you searched for even when nothing was found. Give a
   concrete `how_to_falsify`.
3. **Primitive roles.** For each `CALLED` signal decide `CENTRAL` (on the main product path),
   `SUPPORTING`, or `INCIDENTAL`. `CENTRAL` is only allowed for `CALLED` signals.
4. **AI assessment.** `AI_CORE` / `AI_SUPPORTING` / `NO_AI_FOUND` / `UNKNOWN`, and name the
   deterministic core (what the system does *without* a model).
5. **Unknowns.** Add questions you could not settle. Never resolve an UNKNOWN by opinion.

Write `analysis/<name>/hypotheses.json` (template in the inference guide), then:

```bash
repo-forensics validate analysis/<name>
```

Fix every reported problem and re-run until it prints `VALID`. The validator rejects
dangling evidence ids, missing counter-evidence, `CONFIRMED` inferences, `CENTRAL` on
non-called signals, components claimed without reading files, components citing another
component's evidence, and stale bindings: `commit_sha` and `evidence_digest` must both match
`report.json`. Evidence ids are sequential, so they only mean something together with the
digest. If the digest changed (new tool version, re-run), re-derive the inferences: never
patch ids by hand.

Then build the HTML report, which renders the inference layer only when the bundle validates:

```bash
repo-forensics render analysis/<name>      # writes analysis/<name>/report.html
```

### 5. Add to the corpus (when comparing repositories)

```bash
repo-forensics corpus add analysis/<name> --corpus corpus/
repo-forensics corpus compare --corpus corpus/     # facts.jsonl, compare.json, compare.html
```

Only pinned bundles enter the corpus; an invalid `hypotheses.json` is dropped (facts only).
Cross-repository statements take the weakest status of their inputs.

### 6. Report to the user

Keep facts and inferences visibly separate:

- **Facts** (from the CLI): commit, languages, entry points, primitives with usage levels,
  cycles, complexity distribution — each with its `EV-xxxx` id.
- **Inferences** (yours): component responsibilities, architecture hypotheses with
  confidence and counter-evidence.
- **Unknowns**: the open questions, which are often the most useful output for follow-up research.

Do not judge algorithmic novelty, product quality or business value here. Those belong to
later review and editorial stages, which consume this evidence pack.

## Reference files

- `references/inference-guide.md` — pattern catalogue with observable signals and counter-signals,
  primitive-role criteria, and the `hypotheses.json` template. Read before step 4.
- `references/evidence-model.md` — statuses, usage levels, file layout, and what each metric
  does and does not mean. Read when interpreting an unusual number or explaining the method.
