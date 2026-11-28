import unittest
from io import BytesIO
from xml.sax.saxutils import escape
from zipfile import ZIP_DEFLATED, ZipFile

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


def _column_name(index):
    result = ""
    index += 1
    while index:
        index, remainder = divmod(index - 1, 26)
        result = chr(65 + remainder) + result
    return result


def workbook_bytes(rows, header=None):
    """Build the minimal OOXML subset consumed by the stdlib parser.

    Keeping fixtures dependency-free ensures the repository-wide test suite
    does not need a workbook-writing package just to import these tests.
    """
    columns = list(ca.GRADED_FIELDS if header is None else header)
    table = [columns]
    table.extend([[row.get(field, "") for field in columns] for row in rows])
    worksheet_rows = []
    for row_number, values in enumerate(table, start=1):
        cells = []
        for column_number, value in enumerate(values):
            reference = f"{_column_name(column_number)}{row_number}"
            text = escape(str(value))
            cells.append(
                f'<c r="{reference}" t="inlineStr"><is><t>{text}</t></is></c>'
            )
        worksheet_rows.append(
            f'<row r="{row_number}">{"".join(cells)}</row>'
        )
    worksheet = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<sheetData>{"".join(worksheet_rows)}</sheetData>'
        '</worksheet>'
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="graded" sheetId="1" r:id="rId1"/></sheets>'
        '</workbook>'
    )
    relationships = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/>'
        '</Relationships>'
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '</Types>'
    )
    stream = BytesIO()
    with ZipFile(stream, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", relationships)
        archive.writestr("xl/worksheets/sheet1.xml", worksheet)
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
        self.assertEqual(diag["data_rows"], 2)
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
