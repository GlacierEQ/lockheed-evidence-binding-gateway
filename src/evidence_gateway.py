
"""Evidence binding gateway — TOCTOU-safe evidence snapshots.

Leveled (L1): versioned store, multi-evidence bind, authorize-all,
immutable snapshot history, content-addressed versions.

Independent reference only — no employer affiliation claimed.
"""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Sequence


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
    version: int = 1

    def content_hash(self) -> str:
        return digest({"id": self.evidence_id, "content": dict(self.content), "version": self.version})


@dataclass(frozen=True)
class BoundDecision:
    decision_id: str
    evidence_id: str
    evidence_hash: str
    action: str
    evidence_version: int


@dataclass(frozen=True)
class MultiBoundDecision:
    decision_id: str
    action: str
    bindings: tuple[tuple[str, str, int], ...]  # id, hash, version

    def fingerprint(self) -> str:
        return digest({"id": self.decision_id, "action": self.action, "b": list(self.bindings)})


class EvidenceBindingGateway:
    def __init__(self) -> None:
        self._store: dict[str, EvidenceSnapshot] = {}
        self._history: dict[str, list[EvidenceSnapshot]] = {}
        self._lock = threading.RLock()

    def put(self, snap: EvidenceSnapshot) -> str:
        with self._lock:
            prev = self._store.get(snap.evidence_id)
            version = 1 if prev is None else prev.version + 1
            # force version monotonic even if caller passes version
            sealed = EvidenceSnapshot(snap.evidence_id, dict(snap.content), version)
            self._store[snap.evidence_id] = sealed
            self._history.setdefault(snap.evidence_id, []).append(sealed)
            return sealed.content_hash()

    def get(self, evidence_id: str) -> EvidenceSnapshot | None:
        with self._lock:
            return self._store.get(evidence_id)

    def history(self, evidence_id: str) -> tuple[EvidenceSnapshot, ...]:
        with self._lock:
            return tuple(self._history.get(evidence_id, ()))

    def bind(self, decision_id: str, evidence_id: str, action: str) -> BoundDecision:
        with self._lock:
            snap = self._store[evidence_id]
            return BoundDecision(
                decision_id, evidence_id, snap.content_hash(), action, snap.version
            )

    def bind_many(
        self, decision_id: str, action: str, evidence_ids: Sequence[str]
    ) -> MultiBoundDecision:
        with self._lock:
            bindings = []
            for eid in evidence_ids:
                snap = self._store[eid]
                bindings.append((eid, snap.content_hash(), snap.version))
            return MultiBoundDecision(decision_id, action, tuple(bindings))

    def authorize(self, decision: BoundDecision) -> tuple[GateVerdict, str | None]:
        with self._lock:
            snap = self._store.get(decision.evidence_id)
            if snap is None:
                return GateVerdict.REFUSE, "EVIDENCE_MISSING"
            if snap.version != decision.evidence_version:
                return GateVerdict.REFUSE, "VERSION_DRIFT"
            if snap.content_hash() != decision.evidence_hash:
                return GateVerdict.REFUSE, "EVIDENCE_MUTATED"
            return GateVerdict.ALLOW, None

    def authorize_multi(self, decision: MultiBoundDecision) -> tuple[GateVerdict, str | None]:
        with self._lock:
            if not decision.bindings:
                return GateVerdict.REFUSE, "EMPTY_BINDINGS"
            for eid, ehash, ver in decision.bindings:
                snap = self._store.get(eid)
                if snap is None:
                    return GateVerdict.REFUSE, f"EVIDENCE_MISSING:{eid}"
                if snap.version != ver:
                    return GateVerdict.REFUSE, f"VERSION_DRIFT:{eid}"
                if snap.content_hash() != ehash:
                    return GateVerdict.REFUSE, f"EVIDENCE_MUTATED:{eid}"
            return GateVerdict.ALLOW, None
