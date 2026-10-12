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

**Tier 2 (`--tier 2`) executes the repository's code** and is opt-in. Measures taken: dependencies
are installed with `pip --only-binary :all:` (no build scripts), the project itself is put on
`PYTHONPATH` instead of being built, the source is a disposable copy, the environment is scrubbed
(no inherited variables or credentials), and each process has CPU-time, file-size and core-dump
limits. What it does **not** do: it is not a container, does not isolate the network, and does not
restrict filesystem access outside its work directory. Use it only on disposable machines; a
container runner (`--network none`, read-only source, non-root) is the planned production mode.

Please report vulnerabilities privately via GitHub Security Advisories on this repository
rather than public issues.
