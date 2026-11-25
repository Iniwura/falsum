import unittest
from itertools import permutations
from falsum.phase5az_realvuln_order_invariance import maximum_pairs, f3


class AssignmentTests(unittest.TestCase):
    def test_augmenting_path_avoids_greedy_loss(self):
        edges = {"a": {1, 2}, "b": {1}, "c": {2, 3}}
        for left in permutations(edges):
            for right in permutations((1, 2, 3)):
                p = maximum_pairs(left, right, lambda a, b: b in edges[a])
                self.assertEqual(len(p), 3)
                self.assertEqual(len(set(p.values())), 3)
                self.assertTrue(all(right[j] in edges[left[i]] for i, j in p.items()))

    def test_unmatched_and_empty(self):
        self.assertEqual(maximum_pairs([], [1], lambda a, b: True), {})
        self.assertEqual(maximum_pairs([1], [], lambda a, b: True), {})
        self.assertEqual(len(maximum_pairs([1, 2], [1], lambda a, b: True)), 1)

    def test_f3_uses_recall_weight(self):
        self.assertEqual(f3(dict(TP=1, FN=0, FP=0)), 100)
        self.assertEqual(f3(dict(TP=0, FN=0, FP=0)), 0)
        self.assertLess(f3(dict(TP=1, FN=1, FP=0)), f3(dict(TP=1, FN=0, FP=1)))
