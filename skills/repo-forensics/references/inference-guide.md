# Inference guide

## Contents
1. Method
2. Pattern catalogue (signals and counter-signals)
3. Primitive roles
4. AI assessment
5. hypotheses.json template

## 0. Vocabularies

Component `roles` and hypothesis `pattern_id` must come from `src/repo_forensics/data/vocab/`.
Each role lists the signal subcategories that can implement it (`implemented_by`); in corpus
comparisons only those count as the role's implementation. Patterns may have a `parent`
(graph-rag → rag) so specializations meet in one family. If nothing fits, use the closest term
and say why in the responsibility; propose a vocabulary change rather than inventing a term.

## 1. Method

For every hypothesis: (a) cite the evidence that suggested it; (b) name what would contradict
it and look for exactly that; (c) record what you found, or what you searched and did not find;
(d) state how a reader could falsify it. Prefer two modest hypotheses to one confident story.
Confidence guide: 0.8–0.95 several independent facts and a failed search for counter-evidence;
0.5–0.7 plausible, one line of evidence; below 0.5 use status UNKNOWN instead.

## 2. Pattern catalogue

| Pattern | Look for (evidence) | Counter-evidence to search |
|---|---|---|
| Layered | `dependency_depth` strictly ordered; upper components (api/cli) depend downward; no import-time component cycles | edges from low-depth to high-depth components; import-time component cycles |
| Hexagonal / ports & adapters | a domain component with no third-party I/O signals; adapters carry storage/http/llm signals and depend on the domain | domain modules carrying storage/http/LLM signals; domain importing adapters |
| Pipeline / ETL | chain of components each consuming the previous; entry points are scripts/workers; filesystem/storage at both ends | many-to-many dependencies; central orchestrator with high fan-out |
| Plugin architecture | entry-point groups, `dynamic-import` signal, registry hub with high fan-in, plugins with low reachability | plugins imported statically by the core |
| Client–server / service | `http` entry points; `http-server` signal; settings/env vars for hosts | no inbound HTTP entry point |
| Worker / task queue | `worker` entry points, `task-queue`/`message-queue` signals | queue libraries only declared, not called |
| RAG | embeddings or LLM signal + vector index/store signal on the same reachable path + document readers | vector store declared only; retrieval not reachable from entry points |
| Agent / tool-calling | LLM signal + `mcp` or tool registries + loop orchestration hub | single request–response LLM calls only |
| Monolith with shared kernel | one hub component used by nearly all others; large component cycle | — (state it as a structure, not a smell) |

## 3. Primitive roles

- **CENTRAL**: `CALLED`, reachable from a product entry point, and on the path that produces the
  product's main output (verify by reading the calling function).
- **SUPPORTING**: `CALLED` but auxiliary (caching, logging, admin tools, ingestion utilities).
- **INCIDENTAL**: imported or called once in a peripheral module.
- **UNKNOWN**: called only via configuration-selected backends, or you did not read the call site.

## 4. AI assessment

- **AI_CORE**: removing the model removes the product's main output.
- **AI_SUPPORTING**: the model enhances a deterministic core (e.g. LLM-generated explanations over
  a deterministic ranking).
- **NO_AI_FOUND**: no AI signal and nothing found while reading entry paths.
- **UNKNOWN**: model selection is runtime configuration or remote.

Always list the `deterministic_core`: graph traversal, scoring, filtering, parsing, etc.

## 5. hypotheses.json template

```json
{
  "schema_version": "0.2.0",
  "commit_sha": "<copy provenance.commit_sha from report.json>",
  "evidence_digest": "<copy evidence_digest from report.json>",
  "components": [
    {
      "name": "<exact component name from report.json>",
      "responsibility": "One sentence on what it does.",
      "roles": ["retrieval"],
      "inputs": ["query text"],
      "outputs": ["ranked chunks"],
      "status": "INFERRED",
      "confidence": 0.7,
      "evidence_ids": ["EV-0042"],
      "files_read": ["src/pkg/retrieval/index.py"]
    }
  ],
  "architecture_hypotheses": [
    {
      "id": "HY-01",
      "pattern_id": "layered",
      "pattern": "layered",
      "claim": "api depends on services which depend on domain; domain depends on nothing internal.",
      "status": "INFERRED",
      "confidence": 0.7,
      "evidence_ids": ["EV-0050", "EV-0051"],
      "counter_evidence_ids": ["EV-0061"],
      "counter_evidence_notes": ["domain imports storage adapters in 2 modules (EV-0061)"],
      "how_to_falsify": "Find an import from domain into api in dependency-graph.json."
    }
  ],
  "primitive_roles": [
    {"signature": "faiss", "role": "CENTRAL", "evidence_ids": ["EV-0031"],
     "rationale": "Index search is called by the query handler reachable from the HTTP entry point."}
  ],
  "ai_assessment": {
    "classification": "AI_SUPPORTING",
    "deterministic_core": ["vector search", "metadata filtering"],
    "evidence_ids": ["EV-0033"],
    "rationale": "The LLM only rewrites retrieved results."
  },
  "unknowns": [
    {"question": "Which embedding model is deployed?", "reason": "Selected via EMBED_MODEL env var."}
  ]
}
```
