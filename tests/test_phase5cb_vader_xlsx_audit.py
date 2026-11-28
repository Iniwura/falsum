import unittest
from io import BytesIO

from openpyxl import Workbook

from falsum import phase5ca_vader_corpus as ca
from falsum.phase5cb_vader_xlsx_audit import parse_workbook, _row_digest


def sample_row():
    row = {field: "" for field in ca.GRADED_FIELDS}
    row.update({
        "Case": "1",
        "ID": "1745335148884",
        "Repository": "https://github.com/owner/repo",
        "CWE": "CWE-79",
        "Severity": "high",
        "Description": "Public source-backed vulnerability case",
    })
    for model in ca.MODELS:
        row[model] = '{"assessment":"bounded source evidence"}'
        row[model + "-explanation"] = "1"
        row[model + "-remediation"] = "3"
        row[model + "-other"] = "1"
        row[model + "-comment"] = "reviewed"
        row[model + "-rating"] = "5"
    return row


def workbook_bytes(rows, header=None):
    book = Workbook()
    sheet = book.active
    sheet.title = "graded"
    sheet.append(list(header or ca.GRADED_FIELDS))
    for row in rows:
        sheet.append([row.get(field, "") for field in (header or ca.GRADED_FIELDS)])
    stream = BytesIO()
    book.save(stream)
    book.close()
    return stream.getvalue()


class Phase5CBWorkbookTests(unittest.TestCase):
    def test_exact_schema_and_score_components_parse(self):
        raw = workbook_bytes([sample_row()])
        rows, diag = parse_workbook(raw)
        self.assertEqual(len(rows), 1)
        self.assertEqual(diag["sheet"], "graded")
        self.assertEqual(diag["header_row"], 1)
        self.assertEqual(diag["malformed_row_count"], 0)
        self.assertEqual(diag["duplicate_stable_id_count"], 0)
        self.assertEqual(diag["incomplete_six_answer_count"], 0)

    def test_duplicate_stable_id_is_not_silently_counted_twice(self):
        row = sample_row()
        rows, diag = parse_workbook(workbook_bytes([row, row]))
        self.assertEqual(len(rows), 1)
        self.assertEqual(diag["duplicate_stable_id_count"], 1)
        self.assertEqual(diag["duplicate_stable_ids"], [row["ID"]])

    def test_invalid_component_total_is_excluded(self):
        row = sample_row()
        row["o3-rating"] = "9"
        rows, diag = parse_workbook(workbook_bytes([row]))
        self.assertEqual(rows, [])
        self.assertEqual(diag["malformed_row_count"], 1)

    def test_wrong_header_fails_closed(self):
        header = list(ca.GRADED_FIELDS)
        header[0] = "case-number"
        with self.assertRaises(ca.VaderCorpusError):
            parse_workbook(workbook_bytes([sample_row()], header=header))

    def test_semantically_equal_numeric_cells_have_same_digest(self):
        excel_row = sample_row()
        csv_row = sample_row()
        excel_row["gpt-4.1-rating"] = "5"
        csv_row["gpt-4.1-rating"] = "5.0"
        self.assertEqual(_row_digest(excel_row), _row_digest(csv_row))


if __name__ == "__main__":
    unittest.main()
