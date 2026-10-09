"""The evidence model: every finding is a claim with a status and its support.

Measurements are facts; architecture is an inference. The four statuses:

CONFIRMED  direct source-code / configuration evidence
SUPPORTED  multiple indirect observations, or a strong heuristic
INFERRED   most plausible interpretation
UNKNOWN    insufficient evidence (never silently upgraded)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

STATUSES = ("CONFIRMED", "SUPPORTED", "INFERRED", "UNKNOWN")
DEFAULT_CONFIDENCE = {"CONFIRMED": 1.0, "SUPPORTED": 0.8, "INFERRED": 0.6, "UNKNOWN": None}


def loc(file: str | None = None, line: int | None = None, symbol: str | None = None,
        detail: str | None = None) -> dict:
    return {k: v for k, v in {"file": file, "line": line, "symbol": symbol, "detail": detail}.items()
            if v is not None}


@dataclass
class Evidence:
    id: str
    phase: str
    kind: str
    claim: str
    status: str
    confidence: float | None
    evidence: list[dict]
    counter_evidence: list[dict]
    tool: str
    source: str = "static_analysis"
    data: dict[str, Any] = field(default_factory=dict)


class EvidenceStore:
    def __init__(self, max_locations: int = 15) -> None:
        self.items: list[Evidence] = []
        self.max_locations = max_locations

    def add(self, phase: str, kind: str, claim: str, status: str, *,
            evidence: list[dict] | None = None, counter: list[dict] | None = None,
            confidence: float | None = None, tool: str = "repo-forensics",
            source: str = "static_analysis", data: dict | None = None) -> str:
        if status not in STATUSES:
            raise ValueError(f"invalid status {status}")
        if status == "UNKNOWN":
            confidence = None
        elif confidence is None:
            confidence = DEFAULT_CONFIDENCE[status]
        ev = list(evidence or [])
        data = dict(data or {})
        if len(ev) > self.max_locations:
            data["locations_total"] = len(ev)
            ev = ev[: self.max_locations]
        item = Evidence(
            id=f"EV-{len(self.items) + 1:04d}", phase=phase, kind=kind, claim=claim,
            status=status, confidence=confidence, evidence=ev,
            counter_evidence=list(counter or []), tool=tool, source=source, data=data,
        )
        self.items.append(item)
        return item.id

    def as_dicts(self) -> list[dict]:
        return [asdict(i) for i in self.items]

    def by_status(self) -> dict[str, int]:
        out = {s: 0 for s in STATUSES}
        for i in self.items:
            out[i.status] += 1
        return out
