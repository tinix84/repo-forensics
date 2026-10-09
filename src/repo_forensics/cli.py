"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="repo-forensics",
                                 description="Evidence-first static reconnaissance of a repository (v0.1: Python).")
    ap.add_argument("--version", action="version", version=f"repo-forensics {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analyze a repository (URL, owner/name, or local path)")
    a.add_argument("target")
    a.add_argument("--ref", help="branch, tag or commit SHA to analyze (remote targets only)")
    a.add_argument("--out", default="analysis", help="output directory (default: ./analysis)")
    a.add_argument("--tier", type=int, choices=[0, 1], default=1,
                   help="0 = pure inspection; 1 = also run static analyzers that never execute repo code (default)")
    a.add_argument("--workdir", type=Path, help="where to clone (default: a temp dir, deleted afterwards)")
    a.add_argument("--keep-clone", action="store_true", help="keep the clone for manual reading")
    a.add_argument("--component-depth", type=int, choices=[1, 2], help="override automatic component granularity")
    a.add_argument("--signatures", help="directory with extra signature YAML files")
    a.add_argument("--quiet", action="store_true")

    v = sub.add_parser("validate", help="validate an analysis directory (and hypotheses.json if present)")
    v.add_argument("out")

    h = sub.add_parser("render", help="(re)build report.html, including hypotheses.json if it validates")
    h.add_argument("out")

    args = ap.parse_args(argv)
    if args.cmd == "analyze":
        from .acquire import AcquireError
        from .analyze import run
        try:
            rep = run(args.target, Path(args.out), ref=args.ref, tier=args.tier, workdir=args.workdir,
                      keep_clone=args.keep_clone, component_depth=args.component_depth,
                      extra_signatures=args.signatures)
        except AcquireError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        if not args.quiet:
            p = rep["provenance"]
            summary = {
                "out": str(Path(args.out).resolve()),
                "commit": p["commit_sha"], "pinned": p["pinned"],
                "production_modules": rep["module_graph"]["production_modules"],
                "components": len(rep["components"]["items"]),
                "entrypoints": len(rep["entrypoints"]),
                "signals": len(rep["signals"]), "smells": len(rep["smells"]),
                "unknowns": len(rep["unknowns"]), "evidence": rep["evidence_summary"],
                "clone_path": p.get("clone_path"),
            }
            print(json.dumps(summary, indent=2))
        return 0
    if args.cmd == "validate":
        from .validate import validate_bundle
        errs = validate_bundle(Path(args.out))
        if errs:
            print("\n".join(errs), file=sys.stderr)
            print(f"INVALID: {len(errs)} problem(s)", file=sys.stderr)
            return 1
        print("VALID")
        return 0
    if args.cmd == "render":
        from .html import render_html
        from .validate import validate_bundle
        errs = validate_bundle(Path(args.out))
        path = render_html(Path(args.out))
        if errs:
            print(f"warning: bundle has {len(errs)} validation problem(s); the inference layer was not rendered",
                  file=sys.stderr)
        print(path)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
