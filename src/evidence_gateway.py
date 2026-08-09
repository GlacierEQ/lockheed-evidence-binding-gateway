"""Evidence binding gateway — TOCTOU-safe evidence snapshots."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


def digest(obj: object) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


class GateVerdict(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


@dataclass(frozen=True)
class EvidenceSnapshot:
    evidence_id: str
    content: Mapping[str, Any]

    def content_hash(self) -> str:
        return digest({"id": self.evidence_id, "content": dict(self.content)})


@dataclass(frozen=True)
class BoundDecision:
    decision_id: str
    evidence_id: str
    evidence_hash: str
    action: str


class EvidenceBindingGateway:
    def __init__(self) -> None:
        self._store: dict[str, EvidenceSnapshot] = {}

    def put(self, snap: EvidenceSnapshot) -> str:
        self._store[snap.evidence_id] = snap
        return snap.content_hash()

    def bind(self, decision_id: str, evidence_id: str, action: str) -> BoundDecision:
        snap = self._store[evidence_id]
        return BoundDecision(decision_id, evidence_id, snap.content_hash(), action)

    def authorize(self, decision: BoundDecision) -> tuple[GateVerdict, str | None]:
        snap = self._store.get(decision.evidence_id)
        if snap is None:
            return GateVerdict.REFUSE, "EVIDENCE_MISSING"
        if snap.content_hash() != decision.evidence_hash:
            return GateVerdict.REFUSE, "EVIDENCE_MUTATED"
        return GateVerdict.ALLOW, None
