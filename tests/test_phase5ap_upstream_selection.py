import copy
import unittest
from falsum import phase5ap_upstream_selection as p


class SelectionTests(unittest.TestCase):
    def sample(self):
        original = [{"path": "dataset/arithmetic/a.sol", "name": "a.sol",
                     "source": "https://example.org/source",
                     "vulnerabilities": [{"category": "arithmetic", "lines": [4]},
                                         {"category": "arithmetic", "lines": [8]}]},
                    {"path": "dataset/arithmetic/b.sol", "name": "b.sol",
                     "source": "https://example.org/other",
                     "vulnerabilities": [{"category": "arithmetic", "lines": [9]}]}]
        manifest = {"items": [{"name": "a.sol", "label": "vulnerable", "category": "arithmetic",
                              "source": p.PREFIX+"dataset/arithmetic/a.sol",
                              "origin": "https://example.org/source", "lines": [8,4], "hint": False}]}
        policies = [{"case":"a.sol", "label":"vulnerable", "hint":False,
                     "predictions":{"verdict_only":"FLAG","count_only":"PASS"}}]
        coverage = [{"case":"a.sol","state":"RECORDED_ANSWER"}]
        return original, manifest, policies, coverage

    def test_omission_is_not_failure_or_evaluated_case(self):
        r = p.measure(*self.sample())
        self.assertEqual(r["omitted_upstream_contracts"], 1)
        a = r["category_table"]["arithmetic"]
        self.assertEqual((a["upstream"], a["selected"], a["verdict_flags"], a["recorded_failures"]),
                         (2,1,1,0))
        self.assertEqual(a["count_only_pass"],1)

    def test_annotation_mismatch_fails_closed(self):
        for key, value in (("lines",[4]), ("lines",[True,8]), ("origin","wrong"),
                           ("category","other"), ("source","https://example.org/a.sol")):
            with self.subTest(key=key):
                a,b,c,d = self.sample()
                b["items"][0][key] = value
                with self.assertRaises(ValueError):
                    p.measure(a,b,c,d)

    def test_duplicate_original_path_rejected(self):
        a,b,c,d = self.sample()
        a.append(copy.deepcopy(a[0]))
        with self.assertRaises(ValueError):
            p.measure(a,b,c,d)

    def test_duplicate_or_missing_case_census_rejected(self):
        a,b,c,d = self.sample()
        with self.assertRaises(ValueError):
            p.measure(a,b,c,[])
        with self.assertRaises(ValueError):
            p.measure(a,b,c+c,d)

    def test_unanswered_is_separate(self):
        a,b,c,d = self.sample()
        d[0]["state"]="INPUT_LIMIT_PREFLIGHT_HOLD"
        c[0]["predictions"]={"verdict_only":"UNKNOWN","count_only":"UNKNOWN"}
        r=p.measure(a,b,c,d)["category_table"]["arithmetic"]
        self.assertEqual((r["preflight_holds"],r["recorded_answers"],r["verdict_flags"]),(1,0,0))


if __name__ == "__main__":
    unittest.main()
