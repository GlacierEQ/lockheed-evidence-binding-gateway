from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from src.signed_evidence_gateway import (
    DirectoryContentAddressedStore,
    EvidenceSourceSigner,
    SignedEvidenceBindingGateway,
    SignedEvidenceReason,
    SourceIdentityAuthority,
    SourceQuorumPolicy,
)


class SignedEvidenceGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.authority = SourceIdentityAuthority(b"root-secret")
        self.source_specs = [
            ("sensor-a", "key-a", "sensor", b"a-secret"),
            ("sensor-b", "key-b", "sensor", b"b-secret"),
            ("reviewer-c", "key-c", "reviewer", b"c-secret"),
        ]
        self.signers = {}
        for source_id, key_id, role, key in self.source_specs:
            self.authority.register_source_key(source_id, key_id, key)
            credential = self.authority.issue_credential(
                source_id,
                key_id,
                role,
                not_before=90.0,
                not_after=200.0,
            )
            self.signers[source_id] = EvidenceSourceSigner(
                source_id, key_id, role, key, credential
            )
        self.store = DirectoryContentAddressedStore(self.tmp.name)
        self.gateway = SignedEvidenceBindingGateway(
            self.authority,
            self.store,
            SourceQuorumPolicy(2, ("sensor", "reviewer")),
            max_evidence_age_seconds=10.0,
            max_future_skew_seconds=0.5,
        )
        self.content = {"measurement": 7, "units": "reference"}

    def attestations(self, observed_at: float = 100.0, valid_until: float = 110.0):
        return (
            self.signers["sensor-a"].attest(
                "evidence-1", 3, self.content,
                observed_at=observed_at, valid_until=valid_until,
            ),
            self.signers["reviewer-c"].attest(
                "evidence-1", 3, self.content,
                observed_at=observed_at, valid_until=valid_until,
            ),
        )

    def bind(self, attestations=None, now: float = 101.0):
        if attestations is None:
            attestations = self.attestations()
        return self.gateway.bind(
            "decision-1",
            "authorize.reference.action",
            "evidence-1",
            3,
            self.content,
            attestations,
            now=now,
        )

    def test_signed_distinct_source_quorum_binds_externalized_content_and_authorizes(self):
        binding, receipt = self.bind()
        self.assertIsNotNone(binding)
        assert binding is not None
        self.assertEqual(receipt.outcome, "BOUND")
        self.assertEqual(binding.source_ids, ("reviewer-c", "sensor-a"))
        self.assertEqual(binding.source_roles, ("reviewer", "sensor"))
        self.assertEqual(binding.cas_provider_id, "directory-cas-reference")
        self.assertEqual(len(binding.content_digest), 64)
        self.assertEqual(len(binding.attestation_fingerprints), 2)

        # Bytes live outside the gateway object and are re-read by digest.
        blob_path = (
            Path(self.tmp.name)
            / binding.content_digest[:2]
            / f"{binding.content_digest}.blob"
        )
        self.assertTrue(blob_path.is_file())
        self.assertGreater(blob_path.stat().st_size, 0)

        allowed = self.gateway.authorize(binding, now=105.0)
        self.assertEqual(allowed.outcome, "ALLOW")
        self.assertIsNone(allowed.reason)
        self.assertEqual(allowed.binding_fingerprint, binding.fingerprint())

    def test_duplicate_source_cannot_inflate_quorum(self):
        first = self.signers["sensor-a"].attest(
            "evidence-1", 3, self.content, observed_at=100.0, valid_until=110.0
        )
        second = self.signers["sensor-a"].attest(
            "evidence-1", 3, self.content, observed_at=100.1, valid_until=110.0
        )
        binding, receipt = self.bind((first, second))
        self.assertIsNone(binding)
        self.assertEqual(receipt.reason, SignedEvidenceReason.DUPLICATE_SOURCE.value)

    def test_required_role_cannot_be_substituted_by_second_sensor(self):
        first = self.signers["sensor-a"].attest(
            "evidence-1", 3, self.content, observed_at=100.0, valid_until=110.0
        )
        second = self.signers["sensor-b"].attest(
            "evidence-1", 3, self.content, observed_at=100.0, valid_until=110.0
        )
        binding, receipt = self.bind((first, second))
        self.assertIsNone(binding)
        self.assertEqual(receipt.reason, SignedEvidenceReason.REQUIRED_ROLE_MISSING.value)

    def test_stale_future_and_expired_attestations_fail_closed(self):
        stale = self.attestations(observed_at=80.0, valid_until=150.0)
        self.assertEqual(
            self.bind(stale, now=101.0)[1].reason,
            SignedEvidenceReason.ATTESTATION_STALE.value,
        )

        future = self.attestations(observed_at=102.0, valid_until=120.0)
        self.assertEqual(
            self.bind(future, now=101.0)[1].reason,
            SignedEvidenceReason.ATTESTATION_FROM_FUTURE.value,
        )

        expired = self.attestations(observed_at=100.0, valid_until=100.5)
        self.assertEqual(
            self.bind(expired, now=101.0)[1].reason,
            SignedEvidenceReason.ATTESTATION_EXPIRED.value,
        )

    def test_tampered_source_signature_and_root_credential_fail(self):
        sensor, reviewer = self.attestations()
        tampered_sig = replace(sensor, source_signature="0" * len(sensor.source_signature))
        self.assertEqual(
            self.bind((tampered_sig, reviewer))[1].reason,
            SignedEvidenceReason.SOURCE_SIGNATURE_INVALID.value,
        )

        bad_credential = replace(
            sensor.credential,
            root_signature="0" * len(sensor.credential.root_signature),
        )
        tampered_credential = replace(sensor, credential=bad_credential)
        self.assertEqual(
            self.bind((tampered_credential, reviewer))[1].reason,
            SignedEvidenceReason.CREDENTIAL_INVALID.value,
        )

    def test_attestation_is_bound_to_exact_evidence_identity_version_and_content(self):
        sensor, reviewer = self.attestations()
        wrong_id = replace(sensor, evidence_id="other")
        self.assertEqual(
            self.bind((wrong_id, reviewer))[1].reason,
            SignedEvidenceReason.EVIDENCE_ID_MISMATCH.value,
        )

        wrong_version = replace(sensor, evidence_version=4)
        self.assertEqual(
            self.bind((wrong_version, reviewer))[1].reason,
            SignedEvidenceReason.EVIDENCE_VERSION_MISMATCH.value,
        )

        other_content = {"measurement": 8, "units": "reference"}
        binding, receipt = self.gateway.bind(
            "decision-1",
            "authorize.reference.action",
            "evidence-1",
            3,
            other_content,
            (sensor, reviewer),
            now=101.0,
        )
        self.assertIsNone(binding)
        self.assertEqual(receipt.reason, SignedEvidenceReason.CONTENT_DIGEST_MISMATCH.value)

    def test_binding_freshness_expires_after_attestation_or_age_deadline(self):
        binding, _ = self.bind()
        assert binding is not None
        self.assertEqual(self.gateway.authorize(binding, now=109.9).outcome, "ALLOW")
        stale = self.gateway.authorize(binding, now=110.01)
        self.assertEqual(stale.outcome, "REFUSED")
        self.assertEqual(stale.reason, SignedEvidenceReason.BINDING_STALE.value)

    def test_missing_or_corrupt_cas_object_refuses_after_binding(self):
        binding, _ = self.bind()
        assert binding is not None
        blob_path = (
            Path(self.tmp.name)
            / binding.content_digest[:2]
            / f"{binding.content_digest}.blob"
        )
        blob_path.unlink()
        missing = self.gateway.authorize(binding, now=105.0)
        self.assertEqual(missing.reason, SignedEvidenceReason.CAS_OBJECT_MISSING.value)

        binding2, _ = self.bind(self.attestations(observed_at=102.0, valid_until=112.0), now=103.0)
        assert binding2 is not None
        blob_path2 = (
            Path(self.tmp.name)
            / binding2.content_digest[:2]
            / f"{binding2.content_digest}.blob"
        )
        blob_path2.write_bytes(b"tampered")
        corrupt = self.gateway.authorize(binding2, now=105.0)
        self.assertEqual(corrupt.reason, SignedEvidenceReason.CAS_OBJECT_CORRUPT.value)

    def test_directory_cas_rejects_non_digest_paths(self):
        with self.assertRaises(ValueError):
            self.store.get("../escape")

    def test_credentials_have_hard_validity_boundaries(self):
        authority = SourceIdentityAuthority(b"root")
        authority.register_source_key("short", "key", b"short-key")
        credential = authority.issue_credential(
            "short", "key", "sensor", not_before=100.0, not_after=102.0
        )
        signer = EvidenceSourceSigner("short", "key", "sensor", b"short-key", credential)
        attestation = signer.attest(
            "evidence-1", 3, self.content, observed_at=100.0, valid_until=110.0
        )
        reviewer = self.attestations()[1]
        gateway = SignedEvidenceBindingGateway(
            authority,
            self.store,
            SourceQuorumPolicy(1),
            max_evidence_age_seconds=10.0,
        )
        _, receipt = gateway.bind(
            "d",
            "act",
            "evidence-1",
            3,
            self.content,
            (attestation,),
            now=103.0,
        )
        self.assertEqual(receipt.reason, SignedEvidenceReason.CREDENTIAL_EXPIRED.value)
        # Reviewer belongs to another root authority and cannot be smuggled in.
        _, foreign = gateway.bind(
            "d",
            "act",
            "evidence-1",
            3,
            self.content,
            (reviewer,),
            now=101.0,
        )
        self.assertEqual(foreign.reason, SignedEvidenceReason.CREDENTIAL_INVALID.value)


if __name__ == "__main__":
    unittest.main()
