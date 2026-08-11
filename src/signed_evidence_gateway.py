"""Signed, freshness-bounded, quorum-backed evidence binding.

This module is additive to :mod:`src.evidence_gateway`.  The original in-memory
version/hash gateway remains unchanged.  This path adds a root-signed source
identity, source-signed evidence attestations, exact freshness bounds, distinct
source quorum, and content-addressed blob-store readback before authorization.

The directory store is a durable filesystem reference implementation of the
blob-store contract.  It demonstrates that evidence bytes are externalized from
the gateway object and re-read by digest; it is not a claim of cloud/object-store
replication or provider-managed durability.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    """Return stable UTF-8 JSON bytes for content-addressed evidence."""

    return json.dumps(
        dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_digest(value: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_bytes(value))


class SignedEvidenceReason(str, Enum):
    NONE = "NONE"
    EMPTY_QUORUM = "EMPTY_QUORUM"
    QUORUM_NOT_MET = "QUORUM_NOT_MET"
    DUPLICATE_SOURCE = "DUPLICATE_SOURCE"
    REQUIRED_ROLE_MISSING = "REQUIRED_ROLE_MISSING"
    EVIDENCE_ID_MISMATCH = "EVIDENCE_ID_MISMATCH"
    EVIDENCE_VERSION_MISMATCH = "EVIDENCE_VERSION_MISMATCH"
    CONTENT_DIGEST_MISMATCH = "CONTENT_DIGEST_MISMATCH"
    CREDENTIAL_INVALID = "CREDENTIAL_INVALID"
    CREDENTIAL_NOT_YET_VALID = "CREDENTIAL_NOT_YET_VALID"
    CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
    SOURCE_SIGNATURE_INVALID = "SOURCE_SIGNATURE_INVALID"
    ATTESTATION_FROM_FUTURE = "ATTESTATION_FROM_FUTURE"
    ATTESTATION_STALE = "ATTESTATION_STALE"
    ATTESTATION_EXPIRED = "ATTESTATION_EXPIRED"
    CAS_WRITE_MISMATCH = "CAS_WRITE_MISMATCH"
    CAS_OBJECT_MISSING = "CAS_OBJECT_MISSING"
    CAS_OBJECT_CORRUPT = "CAS_OBJECT_CORRUPT"
    BINDING_STALE = "BINDING_STALE"


@dataclass(frozen=True)
class SourceCredential:
    source_id: str
    key_id: str
    role: str
    not_before: float
    not_after: float
    root_signature: str

    def unsigned_body(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "key_id": self.key_id,
            "role": self.role,
            "not_before": self.not_before,
            "not_after": self.not_after,
        }

    def fingerprint(self) -> str:
        return canonical_digest(
            {
                **self.unsigned_body(),
                "root_signature_digest": sha256_bytes(self.root_signature.encode()),
            }
        )


@dataclass(frozen=True)
class EvidenceAttestation:
    source_id: str
    key_id: str
    role: str
    evidence_id: str
    evidence_version: int
    content_digest: str
    observed_at: float
    valid_until: float
    nonce: str
    source_signature: str
    credential: SourceCredential

    def unsigned_body(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "key_id": self.key_id,
            "role": self.role,
            "evidence_id": self.evidence_id,
            "evidence_version": self.evidence_version,
            "content_digest": self.content_digest,
            "observed_at": self.observed_at,
            "valid_until": self.valid_until,
            "nonce": self.nonce,
            "credential_fingerprint": self.credential.fingerprint(),
        }

    def payload_digest(self) -> str:
        return canonical_digest(self.unsigned_body())

    def fingerprint(self) -> str:
        return canonical_digest(
            {
                **self.unsigned_body(),
                "source_signature_digest": sha256_bytes(self.source_signature.encode()),
            }
        )


class SourceIdentityAuthority:
    """Reference root authority for source credentials and source-key verification.

    HMAC is used only as a deterministic independent-reference mechanism.  The
    authority boundary is intentionally explicit so a KMS/PKI-backed verifier can
    replace it without changing evidence-binding semantics.
    """

    def __init__(self, root_secret: bytes) -> None:
        if not root_secret:
            raise ValueError("root_secret required")
        self._root_secret = root_secret
        self._source_keys: dict[tuple[str, str], bytes] = {}
        self._lock = threading.RLock()

    def register_source_key(self, source_id: str, key_id: str, key: bytes) -> None:
        if not source_id or not key_id or not key:
            raise ValueError("source_id, key_id, and key are required")
        with self._lock:
            self._source_keys[(source_id, key_id)] = key

    def issue_credential(
        self,
        source_id: str,
        key_id: str,
        role: str,
        *,
        not_before: float,
        not_after: float,
    ) -> SourceCredential:
        if not source_id or not key_id or not role:
            raise ValueError("source_id, key_id, and role are required")
        if not_before >= not_after:
            raise ValueError("credential validity interval must be positive")
        with self._lock:
            if (source_id, key_id) not in self._source_keys:
                raise KeyError("source key is not registered")
        unsigned = {
            "source_id": source_id,
            "key_id": key_id,
            "role": role,
            "not_before": not_before,
            "not_after": not_after,
        }
        signature = hmac.new(
            self._root_secret,
            canonical_digest(unsigned).encode(),
            hashlib.sha256,
        ).hexdigest()
        return SourceCredential(**unsigned, root_signature=signature)

    def verify_credential(self, credential: SourceCredential) -> bool:
        expected = hmac.new(
            self._root_secret,
            canonical_digest(credential.unsigned_body()).encode(),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, credential.root_signature):
            return False
        with self._lock:
            return (credential.source_id, credential.key_id) in self._source_keys

    def verify_source_signature(
        self, attestation: EvidenceAttestation
    ) -> bool:
        with self._lock:
            key = self._source_keys.get((attestation.source_id, attestation.key_id))
        if key is None:
            return False
        expected = hmac.new(
            key, attestation.payload_digest().encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, attestation.source_signature)


class EvidenceSourceSigner:
    """Reference source signer bound to a root-issued source credential."""

    def __init__(
        self,
        source_id: str,
        key_id: str,
        role: str,
        source_key: bytes,
        credential: SourceCredential,
    ) -> None:
        if not source_key:
            raise ValueError("source_key required")
        if (
            credential.source_id != source_id
            or credential.key_id != key_id
            or credential.role != role
        ):
            raise ValueError("credential does not match signer identity")
        self.source_id = source_id
        self.key_id = key_id
        self.role = role
        self._source_key = source_key
        self.credential = credential
        self._seq = 0
        self._lock = threading.RLock()

    def attest(
        self,
        evidence_id: str,
        evidence_version: int,
        content: Mapping[str, Any],
        *,
        observed_at: float,
        valid_until: float,
    ) -> EvidenceAttestation:
        if not evidence_id or evidence_version < 1:
            raise ValueError("evidence_id and positive version required")
        if observed_at >= valid_until:
            raise ValueError("attestation validity interval must be positive")
        with self._lock:
            self._seq += 1
            nonce = f"{self.source_id}:{self._seq:08d}"
        unsigned = {
            "source_id": self.source_id,
            "key_id": self.key_id,
            "role": self.role,
            "evidence_id": evidence_id,
            "evidence_version": evidence_version,
            "content_digest": canonical_digest(content),
            "observed_at": observed_at,
            "valid_until": valid_until,
            "nonce": nonce,
            "credential_fingerprint": self.credential.fingerprint(),
        }
        signature = hmac.new(
            self._source_key,
            canonical_digest(unsigned).encode(),
            hashlib.sha256,
        ).hexdigest()
        return EvidenceAttestation(
            source_id=self.source_id,
            key_id=self.key_id,
            role=self.role,
            evidence_id=evidence_id,
            evidence_version=evidence_version,
            content_digest=unsigned["content_digest"],
            observed_at=observed_at,
            valid_until=valid_until,
            nonce=nonce,
            source_signature=signature,
            credential=self.credential,
        )


class ContentAddressedStore(Protocol):
    provider_id: str

    def put(self, content: bytes) -> str: ...

    def get(self, content_digest: str) -> bytes | None: ...


class DirectoryContentAddressedStore:
    """Filesystem-backed content-addressed store with digest readback checks."""

    provider_id = "directory-cas-reference"

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    @staticmethod
    def _validate_digest(content_digest: str) -> None:
        if len(content_digest) != 64 or any(
            char not in "0123456789abcdef" for char in content_digest
        ):
            raise ValueError("invalid SHA-256 digest")

    def _path(self, content_digest: str) -> Path:
        self._validate_digest(content_digest)
        return self.root / content_digest[:2] / f"{content_digest}.blob"

    def put(self, content: bytes) -> str:
        content_digest = sha256_bytes(content)
        path = self._path(content_digest)
        with self._lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                existing = path.read_bytes()
                if sha256_bytes(existing) != content_digest:
                    raise ValueError("existing CAS object is corrupt")
            else:
                tmp = path.with_suffix(".tmp")
                tmp.write_bytes(content)
                os.replace(tmp, path)
            readback = path.read_bytes()
        if sha256_bytes(readback) != content_digest:
            raise ValueError("CAS readback digest mismatch")
        return content_digest

    def get(self, content_digest: str) -> bytes | None:
        path = self._path(content_digest)
        with self._lock:
            if not path.exists():
                return None
            data = path.read_bytes()
        if sha256_bytes(data) != content_digest:
            raise ValueError("CAS object digest mismatch")
        return data


@dataclass(frozen=True)
class SourceQuorumPolicy:
    required_count: int
    required_roles: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.required_count < 1:
            raise ValueError("required_count must be positive")
        roles = tuple(sorted(set(self.required_roles)))
        if any(not role for role in roles):
            raise ValueError("required roles must be non-empty")
        object.__setattr__(self, "required_roles", roles)


@dataclass(frozen=True)
class SignedEvidenceBinding:
    decision_id: str
    action: str
    evidence_id: str
    evidence_version: int
    content_digest: str
    cas_provider_id: str
    source_ids: tuple[str, ...]
    source_roles: tuple[str, ...]
    attestation_fingerprints: tuple[str, ...]
    bound_at: float
    fresh_until: float

    def fingerprint(self) -> str:
        return canonical_digest(
            {
                "decision_id": self.decision_id,
                "action": self.action,
                "evidence_id": self.evidence_id,
                "evidence_version": self.evidence_version,
                "content_digest": self.content_digest,
                "cas_provider_id": self.cas_provider_id,
                "source_ids": self.source_ids,
                "source_roles": self.source_roles,
                "attestation_fingerprints": self.attestation_fingerprints,
                "bound_at": self.bound_at,
                "fresh_until": self.fresh_until,
            }
        )


@dataclass(frozen=True)
class SignedEvidenceReceipt:
    outcome: str  # BOUND | ALLOW | REFUSED
    reason: str | None
    decision_id: str
    evidence_id: str
    content_digest: str | None
    source_ids: tuple[str, ...]
    binding_fingerprint: str | None
    observed_at: float
    fingerprint: str


class SignedEvidenceBindingGateway:
    """Bind actions only to fresh, signed, quorum-backed CAS evidence."""

    def __init__(
        self,
        authority: SourceIdentityAuthority,
        store: ContentAddressedStore,
        quorum: SourceQuorumPolicy,
        *,
        max_evidence_age_seconds: float,
        max_future_skew_seconds: float = 1.0,
    ) -> None:
        if max_evidence_age_seconds <= 0 or max_future_skew_seconds < 0:
            raise ValueError("freshness bounds are invalid")
        self.authority = authority
        self.store = store
        self.quorum = quorum
        self.max_evidence_age_seconds = max_evidence_age_seconds
        self.max_future_skew_seconds = max_future_skew_seconds
        self._audit: list[SignedEvidenceReceipt] = []
        self._lock = threading.RLock()

    def bind(
        self,
        decision_id: str,
        action: str,
        evidence_id: str,
        evidence_version: int,
        content: Mapping[str, Any],
        attestations: Sequence[EvidenceAttestation],
        *,
        now: float,
    ) -> tuple[SignedEvidenceBinding | None, SignedEvidenceReceipt]:
        content_bytes = canonical_bytes(content)
        content_digest = sha256_bytes(content_bytes)
        if not attestations:
            return None, self._refuse(
                SignedEvidenceReason.EMPTY_QUORUM,
                decision_id,
                evidence_id,
                content_digest,
                (),
                now,
            )

        seen: set[str] = set()
        roles: set[str] = set()
        fingerprints: list[str] = []
        fresh_deadlines: list[float] = []
        for attestation in attestations:
            if attestation.source_id in seen:
                return None, self._refuse(
                    SignedEvidenceReason.DUPLICATE_SOURCE,
                    decision_id,
                    evidence_id,
                    content_digest,
                    tuple(sorted(seen | {attestation.source_id})),
                    now,
                )
            seen.add(attestation.source_id)
            reason = self._validate_attestation(
                attestation,
                evidence_id,
                evidence_version,
                content_digest,
                now,
            )
            if reason is not SignedEvidenceReason.NONE:
                return None, self._refuse(
                    reason,
                    decision_id,
                    evidence_id,
                    content_digest,
                    tuple(sorted(seen)),
                    now,
                )
            roles.add(attestation.role)
            fingerprints.append(attestation.fingerprint())
            credential = attestation.credential
            fresh_deadlines.extend(
                (
                    attestation.valid_until,
                    credential.not_after,
                    attestation.observed_at + self.max_evidence_age_seconds,
                )
            )

        if len(seen) < self.quorum.required_count:
            return None, self._refuse(
                SignedEvidenceReason.QUORUM_NOT_MET,
                decision_id,
                evidence_id,
                content_digest,
                tuple(sorted(seen)),
                now,
            )
        if not set(self.quorum.required_roles).issubset(roles):
            return None, self._refuse(
                SignedEvidenceReason.REQUIRED_ROLE_MISSING,
                decision_id,
                evidence_id,
                content_digest,
                tuple(sorted(seen)),
                now,
            )

        try:
            cas_digest = self.store.put(content_bytes)
        except ValueError:
            return None, self._refuse(
                SignedEvidenceReason.CAS_WRITE_MISMATCH,
                decision_id,
                evidence_id,
                content_digest,
                tuple(sorted(seen)),
                now,
            )
        if cas_digest != content_digest:
            return None, self._refuse(
                SignedEvidenceReason.CAS_WRITE_MISMATCH,
                decision_id,
                evidence_id,
                content_digest,
                tuple(sorted(seen)),
                now,
            )
        try:
            readback = self.store.get(content_digest)
        except ValueError:
            return None, self._refuse(
                SignedEvidenceReason.CAS_OBJECT_CORRUPT,
                decision_id,
                evidence_id,
                content_digest,
                tuple(sorted(seen)),
                now,
            )
        if readback is None:
            return None, self._refuse(
                SignedEvidenceReason.CAS_OBJECT_MISSING,
                decision_id,
                evidence_id,
                content_digest,
                tuple(sorted(seen)),
                now,
            )
        if sha256_bytes(readback) != content_digest:
            return None, self._refuse(
                SignedEvidenceReason.CAS_OBJECT_CORRUPT,
                decision_id,
                evidence_id,
                content_digest,
                tuple(sorted(seen)),
                now,
            )

        binding = SignedEvidenceBinding(
            decision_id=decision_id,
            action=action,
            evidence_id=evidence_id,
            evidence_version=evidence_version,
            content_digest=content_digest,
            cas_provider_id=self.store.provider_id,
            source_ids=tuple(sorted(seen)),
            source_roles=tuple(sorted(roles)),
            attestation_fingerprints=tuple(sorted(fingerprints)),
            bound_at=now,
            fresh_until=min(fresh_deadlines),
        )
        receipt = self._receipt(
            "BOUND",
            None,
            decision_id,
            evidence_id,
            content_digest,
            binding.source_ids,
            binding.fingerprint(),
            now,
        )
        self._append(receipt)
        return binding, receipt

    def authorize(
        self, binding: SignedEvidenceBinding, *, now: float
    ) -> SignedEvidenceReceipt:
        if now > binding.fresh_until:
            return self._refuse(
                SignedEvidenceReason.BINDING_STALE,
                binding.decision_id,
                binding.evidence_id,
                binding.content_digest,
                binding.source_ids,
                now,
                binding.fingerprint(),
            )
        try:
            content = self.store.get(binding.content_digest)
        except ValueError:
            return self._refuse(
                SignedEvidenceReason.CAS_OBJECT_CORRUPT,
                binding.decision_id,
                binding.evidence_id,
                binding.content_digest,
                binding.source_ids,
                now,
                binding.fingerprint(),
            )
        if content is None:
            return self._refuse(
                SignedEvidenceReason.CAS_OBJECT_MISSING,
                binding.decision_id,
                binding.evidence_id,
                binding.content_digest,
                binding.source_ids,
                now,
                binding.fingerprint(),
            )
        if sha256_bytes(content) != binding.content_digest:
            return self._refuse(
                SignedEvidenceReason.CAS_OBJECT_CORRUPT,
                binding.decision_id,
                binding.evidence_id,
                binding.content_digest,
                binding.source_ids,
                now,
                binding.fingerprint(),
            )
        receipt = self._receipt(
            "ALLOW",
            None,
            binding.decision_id,
            binding.evidence_id,
            binding.content_digest,
            binding.source_ids,
            binding.fingerprint(),
            now,
        )
        self._append(receipt)
        return receipt

    def audit_trail(self) -> tuple[SignedEvidenceReceipt, ...]:
        with self._lock:
            return tuple(self._audit)

    def _validate_attestation(
        self,
        attestation: EvidenceAttestation,
        evidence_id: str,
        evidence_version: int,
        content_digest: str,
        now: float,
    ) -> SignedEvidenceReason:
        credential = attestation.credential
        if (
            credential.source_id != attestation.source_id
            or credential.key_id != attestation.key_id
            or credential.role != attestation.role
        ):
            return SignedEvidenceReason.CREDENTIAL_INVALID
        if not self.authority.verify_credential(credential):
            return SignedEvidenceReason.CREDENTIAL_INVALID
        if now < credential.not_before:
            return SignedEvidenceReason.CREDENTIAL_NOT_YET_VALID
        if now > credential.not_after:
            return SignedEvidenceReason.CREDENTIAL_EXPIRED
        if attestation.evidence_id != evidence_id:
            return SignedEvidenceReason.EVIDENCE_ID_MISMATCH
        if attestation.evidence_version != evidence_version:
            return SignedEvidenceReason.EVIDENCE_VERSION_MISMATCH
        if attestation.content_digest != content_digest:
            return SignedEvidenceReason.CONTENT_DIGEST_MISMATCH
        if attestation.observed_at > now + self.max_future_skew_seconds:
            return SignedEvidenceReason.ATTESTATION_FROM_FUTURE
        if now - attestation.observed_at > self.max_evidence_age_seconds:
            return SignedEvidenceReason.ATTESTATION_STALE
        if now > attestation.valid_until:
            return SignedEvidenceReason.ATTESTATION_EXPIRED
        if not self.authority.verify_source_signature(attestation):
            return SignedEvidenceReason.SOURCE_SIGNATURE_INVALID
        return SignedEvidenceReason.NONE

    def _refuse(
        self,
        reason: SignedEvidenceReason,
        decision_id: str,
        evidence_id: str,
        content_digest: str | None,
        source_ids: tuple[str, ...],
        now: float,
        binding_fingerprint: str | None = None,
    ) -> SignedEvidenceReceipt:
        receipt = self._receipt(
            "REFUSED",
            reason.value,
            decision_id,
            evidence_id,
            content_digest,
            source_ids,
            binding_fingerprint,
            now,
        )
        self._append(receipt)
        return receipt

    def _receipt(
        self,
        outcome: str,
        reason: str | None,
        decision_id: str,
        evidence_id: str,
        content_digest: str | None,
        source_ids: tuple[str, ...],
        binding_fingerprint: str | None,
        now: float,
    ) -> SignedEvidenceReceipt:
        body = {
            "outcome": outcome,
            "reason": reason,
            "decision_id": decision_id,
            "evidence_id": evidence_id,
            "content_digest": content_digest,
            "source_ids": source_ids,
            "binding_fingerprint": binding_fingerprint,
            "observed_at": now,
        }
        return SignedEvidenceReceipt(
            outcome=outcome,
            reason=reason,
            decision_id=decision_id,
            evidence_id=evidence_id,
            content_digest=content_digest,
            source_ids=source_ids,
            binding_fingerprint=binding_fingerprint,
            observed_at=now,
            fingerprint=canonical_digest(body),
        )

    def _append(self, receipt: SignedEvidenceReceipt) -> None:
        with self._lock:
            self._audit.append(receipt)
