import unittest
from modelaudit import auc, audit, check_draft_numbers, fairness, psi, revalidate


class AuditTests(unittest.TestCase):
    def test_metrics(self):
        self.assertEqual(auc([0, 1], [.1, .9]), 1)
        self.assertAlmostEqual(psi([.1, .9], [.1, .9]), 0)
        f = fairness([1, 1, 0, 0], [1, 0, 1, 0], ["A", "B", "A", "B"])
        self.assertEqual(f["equal_opportunity_difference"], 1)

    def test_number_guard(self):
        self.assertTrue(check_draft_numbers("AUC 0.8", {"auc": .8}))
        self.assertFalse(check_draft_numbers("AUC 0.9", {"auc": .8}))

    def test_finding_trace(self):
        result = revalidate(audit(7), 8)
        self.assertTrue(result["findings"])
        self.assertTrue(all(f["test_id"] in result["tests"] for f in result["findings"]))
        self.assertTrue(all(f["status"] in {"reproduced", "not reproduced"} for f in result["findings"]))


if __name__ == "__main__":
    unittest.main()
