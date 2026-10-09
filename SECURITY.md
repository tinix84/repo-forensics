# Security model

`repo-forensics` analyzes repositories it does not trust. Design rules:

1. **No code from the analyzed repository is executed** at tier 0 or 1. Python files are parsed
   with `ast.parse`; `setup.py` is read as AST and its `setup()` literals extracted, never run.
   Tier 1 adds lizard, which tokenizes text.
2. **Acquisition** fetches exactly one commit (`--depth 1`), with `core.hooksPath=/dev/null`,
   `protocol.file.allow=never`, `core.symlinks=false`, no submodules, no tags, `GIT_LFS_SKIP_SMUDGE=1`,
   and no interactive credential prompts.
3. **Symlinks** are excluded from analysis; files above the parse size limit are skipped and reported.
4. **Credentials** embedded in remote URLs are stripped before being written to any report.

Not yet implemented: resource limits (CPU/memory) on parsing pathological inputs. A planned
tier 2 (builds, tests) will run only in a disposable, non-root, network-less container.

Please report vulnerabilities privately via GitHub Security Advisories on this repository
rather than public issues.
