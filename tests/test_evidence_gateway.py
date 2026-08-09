from __future__ import annotations
import unittest
from src.evidence_gateway import EvidenceBindingGateway, EvidenceSnapshot, GateVerdict

class EvTests(unittest.TestCase):
    def test_mutation_refuses(self):
        g = EvidenceBindingGateway()
        g.put(EvidenceSnapshot("e1", {"t": 1}))
        d = g.bind("d1", "e1", "act")
        g.put(EvidenceSnapshot("e1", {"t": 2}))
        v, r = g.authorize(d)
        self.assertEqual(v, GateVerdict.REFUSE)
        self.assertEqual(r, "EVIDENCE_MUTATED")

    def test_allow(self):
        g = EvidenceBindingGateway()
        g.put(EvidenceSnapshot("e1", {"t": 1}))
        d = g.bind("d1", "e1", "act")
        v, r = g.authorize(d)
        self.assertEqual(v, GateVerdict.ALLOW)

if __name__ == "__main__":
    unittest.main()
