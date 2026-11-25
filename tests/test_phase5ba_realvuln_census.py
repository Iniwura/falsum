import unittest
from falsum.phase5ba_realvuln_census import target_ids


class CensusTests(unittest.TestCase):
    def test_disjoint_complete_selection(self):
        manifest = {"repos": {
            "z": {"language": "python", "authorship": "human_authored"},
            "a": {"language": "python", "authorship": "human_authored"},
            "pilot": {"language": "python", "authorship": "human_authored"},
            "generated": {"language": "python", "authorship": "llm_generated"},
            "java": {"language": "java", "authorship": "human_authored"},
        }}
        self.assertEqual(target_ids(manifest, ["pilot"]), ["a", "z"])

    def test_empty_census(self):
        self.assertEqual(target_ids({"repos": {}}, []), [])
