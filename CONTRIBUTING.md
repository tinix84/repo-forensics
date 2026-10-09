# Contributing

```bash
pip install -e ".[dev]"
ruff check . && pytest
repo-forensics analyze . --out /tmp/self && repo-forensics validate /tmp/self   # dogfood
```

**Adding a library signature**: edit `src/repo_forensics/data/signatures/*.yaml`. Use the
canonical primitive name (what it *is*, e.g. `approximate-nearest-neighbor`), not the product.
Module prefixes match imports and qualified calls; `refine` maps call prefixes to sub-primitives.
Add a fixture line in `tests/conftest.py` if the signature needs a new detection path.

**Rule of the project**: deterministic code may emit CONFIRMED evidence only for direct
observations. Anything interpretive is INFERRED or SUPPORTED and carries counter-evidence.
If a heuristic is wrong on a real repository, add that case to the synthetic fixture first.
