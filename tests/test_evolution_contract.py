from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE_PATH = ROOT / "machine" / "excellence-state.json"
TARGET_PATH = ROOT / "machine" / "target-contract.json"
POSITION_PATH = ROOT / "machine" / "role-position.json"
RECEIPT_PATH = (
    ROOT
    / "machine"
    / "evolution-receipts"
    / "2026-08-11-signed-source-quorum-cas.json"
)

CONSUMED = (
    "next:signed_evidence_identity_freshness_external_content_addressed_storage_"
    "source_quorum"
)
NEXT = (
    "next:remote_kms_pki_identity_source_key_revocation_freshness_provider_"
    "attested_object_store_replication_and_distributed_source_quorum_reconciliation"
)
CANDIDATE = "c862c106343c1b80c696904b09225f0f44d125ba"
RUN = 31542803628


class EvolutionContractTests(unittest.TestCase):
    def load(self, path: Path) -> dict:
        raw = path.read_text(encoding="utf-8")
        self.assertNotIn("<<<<<<<", raw)
        self.assertNotIn("=======", raw)
        self.assertNotIn(">>>>>>>", raw)
        return json.loads(raw)

    def test_receipt_is_bound_to_exact_candidate(self):
        receipt = self.load(RECEIPT_PATH)
        self.assertEqual(
            receipt["repository"], "GlacierEQ/lockheed-evidence-binding-gateway"
        )
        self.assertEqual(receipt["consumed_cursor"], CONSUMED)
        self.assertEqual(receipt["candidate_source_sha"], CANDIDATE)
        self.assertEqual(receipt["workflow_run"], RUN)
        self.assertEqual(receipt["python"], "PASS")
        self.assertEqual(receipt["next_cursor"], NEXT)

    def test_state_target_and_position_advance_together(self):
        state = self.load(STATE_PATH)
        target = self.load(TARGET_PATH)
        position = self.load(POSITION_PATH)
        self.assertEqual(state["principal_state"], "EVOLVING")
        self.assertEqual(state["evolution_cursor"], NEXT)
        self.assertEqual(
            state["evolution_history"][-1]["candidate_source_sha"], CANDIDATE
        )
        self.assertEqual(state["evolution_history"][-1]["workflow_run"], RUN)
        self.assertEqual(target["identity"]["repository_id"], state["repository"])
        self.assertEqual(target["current"]["state"], "EVOLVING")
        self.assertEqual(target["proof"]["candidate_source_sha"], CANDIDATE)
        self.assertEqual(target["proof"]["workflow_run"], RUN)
        self.assertEqual(target["next_cursor"], NEXT)
        self.assertEqual(position["evolution"]["candidate_source_sha"], CANDIDATE)
        self.assertEqual(position["evolution"]["workflow_run"], RUN)

    def test_external_identity_storage_and_quorum_claims_remain_bounded(self):
        receipt = self.load(RECEIPT_PATH)
        target = self.load(TARGET_PATH)
        boundaries = " ".join(receipt["truth_boundaries"]).lower()
        self.assertIn("rather than production pki or kms-backed identity", boundaries)
        self.assertIn("not cloud object-store replication", boundaries)
        self.assertIn("not distributed or consensus reconciled", boundaries)
        nonclaims = " ".join(target["nonclaims"]).lower()
        self.assertIn("no production pki or kms-backed source identity", nonclaims)
        self.assertIn("no live source-key revocation feed", nonclaims)
        self.assertIn("no cloud object-store replication", nonclaims)
        self.assertIn("no distributed or consensus-reconciled source quorum", nonclaims)


if __name__ == "__main__":
    unittest.main()
