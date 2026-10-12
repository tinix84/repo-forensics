"""Generic SARIF 2.1.0 reader: one parser for every tool that can emit SARIF."""

from __future__ import annotations

import json
from pathlib import Path

from . import Finding, rel


def parse_sarif(text: str, root: Path) -> tuple[list[Finding], str | None]:
    data = json.loads(text)
    out: list[Finding] = []
    version = None
    for run in data.get("runs", []):
        driver = (run.get("tool") or {}).get("driver") or {}
        name = driver.get("name", "sarif")
        version = driver.get("version") or version
        for r in run.get("results", []):
            loc = (r.get("locations") or [{}])[0].get("physicalLocation") or {}
            region = loc.get("region") or {}
            out.append(
                Finding(
                    tool=name,
                    rule=r.get("ruleId") or "?",
                    message=((r.get("message") or {}).get("text") or "")[:300],
                    file=rel((loc.get("artifactLocation") or {}).get("uri"), root),
                    line=region.get("startLine"),
                    level=r.get("level") or "warning",
                )
            )
    return out, version
