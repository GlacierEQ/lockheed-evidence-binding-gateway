"""Evidence binding gateway — TOCTOU-safe evidence snapshots with cryptographic verification.

Leveled (L1): versioned store, multi-evidence bind, authorize-all,
immutable snapshot history, content-addressed versions, audit trail logging.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence


def digest(obj: object) -> str:
    """Computes a deterministic SHA-256 hex digest for JSON-serializable objects."""
    serialized = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class GateVerdict(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


@dataclass(frozen=True)
class EvidenceSnapshot:
    evidence_id: str
    content: Mapping[str, Any]
    version: int = 1
    timestamp: float = field(default_factory=time.time)

    def content_hash(self) -> str:
        return digest({
            "id": self.evidence_id,
            "content": dict(self.content),
            "version": self.version
        })


@dataclass(frozen=True)
class BoundDecision:
    decision_id: str
    evidence_id: str
    evidence_hash: str
    action: str
    evidence_version: int
    bound_at: float = field(default_factory=time.time)


@dataclass(frozen=True)
class MultiBoundDecision:
    decision_id: str
    action: str
    bindings: tuple[tuple[str, str, int], ...]  # (id, hash, version)
    bound_at: float = field(default_factory=time.time)

    def fingerprint(self) -> str:
        return digest({
            "id": self.decision_id,
            "action": self.action,
            "b": list(self.bindings)
        })


@dataclass(frozen=True)
class AuditEntry:
    decision_id: str
    action: str
    verdict: GateVerdict
    reason: str | None
    timestamp: float = field(default_factory=time.time)


class EvidenceBindingGateway:
    """Thread-safe state store & authorization engine for evidence snapshots."""

    def __init__(self) -> None:
        self._store: dict[str, EvidenceSnapshot] = {}
        self._history: dict[str, list[EvidenceSnapshot]] = {}
        self._audit_log: list[AuditEntry] = []
        self._lock = threading.RLock()

    def put(self, snap: EvidenceSnapshot) -> str:
        """Stores a snapshot, maintaining monotonic versioning and immutable history."""
        with self._lock:
            prev = self._store.get(snap.evidence_id)
            version = 1 if prev is None else prev.version + 1
            sealed = EvidenceSnapshot(
                evidence_id=snap.evidence_id,
                content=dict(snap.content),
                version=version,
                timestamp=time.time()
            )
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
            snap = self._store.get(evidence_id)
            if snap is None:
                raise KeyError(f"Evidence '{evidence_id}' does not exist in gateway store")
            return BoundDecision(
                decision_id=decision_id,
                evidence_id=evidence_id,
                evidence_hash=snap.content_hash(),
                action=action,
                evidence_version=snap.version,
            )

    def bind_many(
        self, decision_id: str, action: str, evidence_ids: Sequence[str]
    ) -> MultiBoundDecision:
        with self._lock:
            bindings: list[tuple[str, str, int]] = []
            for eid in evidence_ids:
                snap = self._store.get(eid)
                if snap is None:
                    raise KeyError(f"Evidence '{eid}' does not exist in gateway store")
                bindings.append((eid, snap.content_hash(), snap.version))
            return MultiBoundDecision(
                decision_id=decision_id,
                action=action,
                bindings=tuple(bindings),
            )

    def authorize(self, decision: BoundDecision) -> tuple[GateVerdict, str | None]:
        with self._lock:
            snap = self._store.get(decision.evidence_id)
            verdict: GateVerdict
            reason: str | None = None

            if snap is None:
                verdict, reason = GateVerdict.REFUSE, "EVIDENCE_MISSING"
            elif snap.version != decision.evidence_version:
                verdict, reason = GateVerdict.REFUSE, "VERSION_DRIFT"
            elif snap.content_hash() != decision.evidence_hash:
                verdict, reason = GateVerdict.REFUSE, "EVIDENCE_MUTATED"
            else:
                verdict, reason = GateVerdict.ALLOW, None

            self._audit_log.append(
                AuditEntry(decision.decision_id, decision.action, verdict, reason)
            )
            return verdict, reason

    def authorize_multi(self, decision: MultiBoundDecision) -> tuple[GateVerdict, str | None]:
        with self._lock:
            verdict: GateVerdict
            reason: str | None = None

            if not decision.bindings:
                verdict, reason = GateVerdict.REFUSE, "EMPTY_BINDINGS"
            else:
                for eid, ehash, ver in decision.bindings:
                    snap = self._store.get(eid)
                    if snap is None:
                        verdict, reason = GateVerdict.REFUSE, f"EVIDENCE_MISSING:{eid}"
                        break
                    if snap.version != ver:
                        verdict, reason = GateVerdict.REFUSE, f"VERSION_DRIFT:{eid}"
                        break
                    if snap.content_hash() != ehash:
                        verdict, reason = GateVerdict.REFUSE, f"EVIDENCE_MUTATED:{eid}"
                        break
                else:
                    verdict, reason = GateVerdict.ALLOW, None

            self._audit_log.append(
                AuditEntry(decision.decision_id, decision.action, verdict, reason)
            )
            return verdict, reason

    def get_audit_trail(self) -> tuple[AuditEntry, ...]:
        with self._lock:
            return tuple(self._audit_log)
