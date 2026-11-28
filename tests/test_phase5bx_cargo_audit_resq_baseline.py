import unittest

from falsum import phase5bx_cargo_audit_resq_baseline as m


def phase5bu_report():
    protocol = m._load_protocol()
    app = protocol["application"]
    rows = []
    for case in protocol["selection"]["case_roster"]:
        rows.append({
            "case_id": case["id"], "package": case["package"], "version": case["version"],
            "advisory": case["advisory"], "falsum_candidate": case["falsum_candidate_status"],
            "semver_7_8_6_reference": case["semver_reference_status"],
            "citation_only_baseline": "APPLICABLE",
        })
    return {
        "status": "PHASE5BU_RESQ_SOLANA_LOCKFILE_COMPATIBILITY",
        "application": {
            "repository": app["repository"], "commit": app["commit"],
            "lockfile_git_blob": app["lockfile_git_blob"], "package": app["package"],
            "resolved_version": app["resolved_version"],
        },
        "rows": rows,
    }


def cargo_report(findings=None):
    findings = findings or []
    return {
        "database": {"advisory-count": 900, "last-commit": None, "last-updated": None},
        "lockfile": {"dependency-count": 312},
        "settings": {"target_arch": None, "target_os": None, "ignore": []},
        "vulnerabilities": {"found": bool(findings), "count": len(findings), "list": findings},
        "warnings": {},
    }


def finding(advisory_id, package="anchor-lang", version="1.0.0-rc.4"):
    return {
        "advisory": {"id": advisory_id, "package": package, "title": "fixture title"},
        "package": {"name": package, "version": version},
        "versions": {"patched": [], "unaffected": []},
    }


class Phase5BXTests(unittest.TestCase):
    def setUp(self):
        self.protocol = m._load_protocol()
        self.database_commit = self.protocol["advisory_database"]["commit"]
        self.database_blobs = {row["id"]: row["blob"]
                               for row in self.protocol["advisory_database"]["advisories"]}

    def evaluate(self, data, **overrides):
        args = {
            "cargo_audit_exit_code": 0,
            "cargo_audit_version": self.protocol["baseline"]["version"],
            "database_commit": self.database_commit,
            "database_blobs": self.database_blobs,
        }
        args.update(overrides)
        return m.evaluate(self.protocol, phase5bu_report(), data, **args)

    def test_no_selected_findings_agrees_with_candidate_and_semver_on_both_pairs(self):
        report = self.evaluate(cargo_report())
        self.assertEqual(report["sample_sizes"]["package_advisory_pairs"], 2)
        self.assertEqual(report["aggregate"]["falsum_coverage"], 2)
        self.assertEqual(report["aggregate"]["falsum_abstentions"], 0)
        self.assertEqual(report["aggregate"]["falsum_cargo_audit_agreement"], 2)
        self.assertEqual(report["aggregate"]["semver_cargo_audit_agreement"], 2)
        self.assertEqual(report["aggregate"]["falsum_false_acceptances_vs_cargo_audit"], 0)
        self.assertEqual(report["aggregate"]["falsum_false_rejections_vs_cargo_audit"], 0)
        self.assertEqual([row["cargo_audit_0_22_2"] for row in report["rows"]],
                         [m.INAPPLICABLE, m.INAPPLICABLE])

    def test_selected_finding_is_reported_as_candidate_disagreement_not_hidden(self):
        report = self.evaluate(cargo_report([finding("RUSTSEC-2026-0144")]),
                               cargo_audit_exit_code=1)
        self.assertEqual(report["aggregate"]["falsum_cargo_audit_agreement"], 1)
        self.assertEqual(report["aggregate"]["falsum_false_rejections_vs_cargo_audit"], 1)
        self.assertEqual(report["rows"][0]["cargo_audit_0_22_2"], m.APPLICABLE)
        self.assertEqual(report["rows"][1]["cargo_audit_0_22_2"], m.INAPPLICABLE)

    def test_full_lockfile_findings_are_retained_outside_the_two_pair_subset(self):
        report = self.evaluate(cargo_report([
            finding("RUSTSEC-2026-0999", package="other-crate", version="2.0.0")
        ]), cargo_audit_exit_code=1)
        self.assertEqual(report["baseline"]["full_lockfile_vulnerability_count"], 1)
        self.assertEqual(report["baseline"]["full_lockfile_findings"][0]["package"], "other-crate")
        self.assertEqual(report["aggregate"]["falsum_cargo_audit_agreement"], 2)

    def test_rejects_count_or_found_flag_mismatch(self):
        malformed = cargo_report()
        malformed["vulnerabilities"]["count"] = 1
        with self.assertRaises(m.CargoAuditBaselineError):
            self.evaluate(malformed)
        malformed = cargo_report()
        malformed["vulnerabilities"]["found"] = True
        with self.assertRaises(m.CargoAuditBaselineError):
            self.evaluate(malformed)

    def test_rejects_selected_advisory_for_wrong_package_or_version(self):
        with self.assertRaises(m.CargoAuditBaselineError):
            self.evaluate(cargo_report([finding("RUSTSEC-2026-0144", package="other-crate")]))
        with self.assertRaises(m.CargoAuditBaselineError):
            self.evaluate(cargo_report([finding("RUSTSEC-2026-0144", version="1.0.0")]))

    def test_rejects_duplicate_selected_finding(self):
        rows = [finding("RUSTSEC-2026-0144"), finding("RUSTSEC-2026-0144")]
        with self.assertRaises(m.CargoAuditBaselineError):
            self.evaluate(cargo_report(rows))

    def test_rejects_wrong_tool_or_database_identity(self):
        with self.assertRaises(m.CargoAuditBaselineError):
            self.evaluate(cargo_report(), cargo_audit_version="0.22.1")
        with self.assertRaises(m.CargoAuditBaselineError):
            self.evaluate(cargo_report(), database_commit="0" * 40)
        with self.assertRaises(m.CargoAuditBaselineError):
            self.evaluate(cargo_report(), database_blobs={})


if __name__ == "__main__":
    unittest.main()
