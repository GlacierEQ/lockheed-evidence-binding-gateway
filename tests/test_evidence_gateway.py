
from __future__ import annotations
import unittest
from src.evidence_gateway import (
    EvidenceBindingGateway, EvidenceSnapshot, GateVerdict,
)

class EvLeveledTests(unittest.TestCase):
    def test_mutation_refuses(self):
        g = EvidenceBindingGateway()
        g.put(EvidenceSnapshot("e1", {"t": 1}))
        d = g.bind("d1", "e1", "act")
        g.put(EvidenceSnapshot("e1", {"t": 2}))
        v, r = g.authorize(d)
        self.assertEqual(v, GateVerdict.REFUSE)
        self.assertIn(r, ("EVIDENCE_MUTATED", "VERSION_DRIFT"))

    def test_allow(self):
        g = EvidenceBindingGateway()
        g.put(EvidenceSnapshot("e1", {"t": 1}))
        d = g.bind("d1", "e1", "act")
        v, r = g.authorize(d)
        self.assertEqual(v, GateVerdict.ALLOW)

    def test_version_monotonic(self):
        g = EvidenceBindingGateway()
        g.put(EvidenceSnapshot("e1", {"t": 1}))
        g.put(EvidenceSnapshot("e1", {"t": 2}))
        hist = g.history("e1")
        self.assertEqual([h.version for h in hist], [1, 2])

    def test_multi_bind_all_required(self):
        g = EvidenceBindingGateway()
        g.put(EvidenceSnapshot("e1", {"a": 1}))
        g.put(EvidenceSnapshot("e2", {"b": 2}))
        d = g.bind_many("d1", "act", ["e1", "e2"])
        self.assertEqual(g.authorize_multi(d)[0], GateVerdict.ALLOW)
        g.put(EvidenceSnapshot("e2", {"b": 3}))
        v, r = g.authorize_multi(d)
        self.assertEqual(v, GateVerdict.REFUSE)
        self.assertTrue(r and "e2" in r)

    def test_missing_evidence(self):
        g = EvidenceBindingGateway()
        g.put(EvidenceSnapshot("e1", {"a": 1}))
        d = g.bind("d1", "e1", "act")
        g._store.clear()  # noqa: SLF001
        self.assertEqual(g.authorize(d)[1], "EVIDENCE_MISSING")

    def test_empty_multi(self):
        g = EvidenceBindingGateway()
        d = g.bind_many("d1", "act", [])
        self.assertEqual(g.authorize_multi(d)[1], "EMPTY_BINDINGS")

if __name__ == "__main__":
    unittest.main()
