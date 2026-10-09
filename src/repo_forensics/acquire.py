"""ACQUIRE: obtain the repository at a pinned commit without executing any of its code.

Safety measures (Tier 0):
- shallow fetch of exactly one commit; no submodules, no tags, no LFS smudge
- hooks disabled, file:// protocol disabled, symlinks checked out as plain files
- no interactive credential prompts
- credentials embedded in remote URLs are stripped before being recorded
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

GIT_TIMEOUT_S = 600
_GIT_SAFE_FLAGS = [
    "-c", "core.hooksPath=/dev/null",
    "-c", "protocol.file.allow=never",
    "-c", "core.symlinks=false",
    "-c", "submodule.recurse=false",
    "-c", "advice.detachedHead=false",
]
_SHORTHAND = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class AcquireError(RuntimeError):
    pass


@dataclass
class Acquired:
    root: Path
    is_git: bool
    url: str | None
    requested_ref: str | None
    commit_sha: str | None
    default_branch: str | None
    dirty: bool | None
    analyzed_at: str
    cloned: bool


def _env() -> dict:
    env = dict(os.environ)
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_ASKPASS": "true"})
    return env


def git(args: list[str], cwd: Path | None = None, check: bool = True) -> str:
    try:
        r = subprocess.run(["git", *_GIT_SAFE_FLAGS, *args], cwd=cwd, env=_env(),
                           capture_output=True, text=True, timeout=GIT_TIMEOUT_S)
    except FileNotFoundError as e:  # pragma: no cover
        raise AcquireError("git executable not found") from e
    except subprocess.TimeoutExpired as e:
        raise AcquireError(f"git {' '.join(args[:2])} timed out") from e
    if check and r.returncode != 0:
        raise AcquireError(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout.strip()


def strip_credentials(url: str | None) -> str | None:
    if not url:
        return url
    return re.sub(r"^(https?://)[^/@]+@", r"\1", url)


def is_remote(target: str) -> bool:
    return (target.startswith(("https://", "http://", "ssh://", "git@"))
            or (bool(_SHORTHAND.match(target)) and not Path(target).exists()))


def normalize_url(target: str) -> str:
    if _SHORTHAND.match(target) and not target.startswith(("https://", "http://")):
        return f"https://github.com/{target}"
    return target


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def clone(target: str, dest: Path, ref: str | None = None) -> Acquired:
    url = normalize_url(target)
    if dest.exists() and any(dest.iterdir()):
        raise AcquireError(f"clone destination {dest} is not empty")
    dest.mkdir(parents=True, exist_ok=True)
    git(["init", "-q", str(dest)])
    git(["remote", "add", "origin", url], cwd=dest)
    default_branch = None
    if ref is None:
        head = git(["ls-remote", "--symref", "origin", "HEAD"], cwd=dest, check=False)
        m = re.search(r"ref:\s+refs/heads/(\S+)\s+HEAD", head)
        default_branch = m.group(1) if m else None
    if ref and re.fullmatch(r"[0-9a-f]{7,39}", ref):
        raise AcquireError(f"'{ref}' looks like an abbreviated commit SHA; a shallow fetch needs the full "
                           "40-character SHA (or a branch/tag name)")
    git(["fetch", "-q", "--depth", "1", "--no-tags", "--no-recurse-submodules",
         "origin", ref or "HEAD"], cwd=dest)
    git(["checkout", "-q", "--detach", "FETCH_HEAD"], cwd=dest)
    sha = git(["rev-parse", "HEAD"], cwd=dest)
    return Acquired(root=dest, is_git=True, url=strip_credentials(url), requested_ref=ref,
                    commit_sha=sha, default_branch=default_branch, dirty=False,
                    analyzed_at=_now(), cloned=True)


def open_local(path: Path) -> Acquired:
    path = path.resolve()
    if not path.is_dir():
        raise AcquireError(f"{path} is not a directory")
    is_git = (path / ".git").exists()
    sha = url = None
    dirty = None
    if is_git:
        sha = git(["rev-parse", "HEAD"], cwd=path, check=False) or None
        url = strip_credentials(git(["config", "--get", "remote.origin.url"], cwd=path, check=False) or None)
        dirty = bool(git(["status", "--porcelain"], cwd=path, check=False))
    return Acquired(root=path, is_git=is_git, url=url, requested_ref=None, commit_sha=sha,
                    default_branch=None, dirty=dirty, analyzed_at=_now(), cloned=False)


def list_files(acq: Acquired) -> list[str]:
    """Tracked + untracked-but-not-ignored files (git) or a filtered walk; symlinks are excluded."""
    root = acq.root
    if acq.is_git:
        out = git(["ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root)
        files = [f for f in out.split("\0") if f]
    else:
        files = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", ".venv", "venv",
                                                            "__pycache__", ".tox", ".mypy_cache"}]
            for fn in filenames:
                files.append(os.path.relpath(os.path.join(dirpath, fn), root))
    result = []
    for f in files:
        p = root / f
        if p.is_symlink() or not p.is_file():
            continue
        result.append(f.replace(os.sep, "/"))
    return sorted(result)


_LICENSE_RULES = [
    ("AGPL-3.0", [r"GNU AFFERO GENERAL PUBLIC LICENSE"]),
    ("LGPL-3.0", [r"GNU LESSER GENERAL PUBLIC LICENSE", r"Version 3"]),
    ("LGPL-2.1", [r"GNU LESSER GENERAL PUBLIC LICENSE", r"Version 2\.1"]),
    ("GPL-3.0", [r"GNU GENERAL PUBLIC LICENSE", r"Version 3"]),
    ("GPL-2.0", [r"GNU GENERAL PUBLIC LICENSE", r"Version 2"]),
    ("Apache-2.0", [r"Apache License", r"Version 2\.0"]),
    ("MPL-2.0", [r"Mozilla Public License,? [Vv]ersion 2\.0"]),
    ("MIT", [r"Permission is hereby granted, free of charge"]),
    ("BSD-3-Clause", [r"Redistribution and use in source and binary forms", r"[Nn]either the name"]),
    ("BSD-2-Clause", [r"Redistribution and use in source and binary forms"]),
    ("ISC", [r"Permission to use, copy, modify, and/or distribute this software"]),
    ("Unlicense", [r"This is free and unencumbered software released into the public domain"]),
]


def detect_license(root: Path, files: list[str]) -> tuple[str | None, str | None]:
    """Return (spdx_guess, file). Heuristic text match on top-level license files."""
    cands = [f for f in files if "/" not in f and re.match(r"(?i)^(licen[cs]e|copying)(\.|$)", f)]
    for f in cands:
        try:
            text = (root / f).read_text(encoding="utf-8", errors="replace")[:6000]
        except OSError:
            continue
        for spdx, pats in _LICENSE_RULES:
            if all(re.search(p, text) for p in pats):
                return spdx, f
        return "UNRECOGNIZED", f
    return None, None
