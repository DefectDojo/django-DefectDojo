"""Helpers for CSV and XLSX exports that are opened in spreadsheet applications."""
import csv

# Leading characters a spreadsheet application may read as the start of a formula.
FORMULA_PREFIXES = frozenset("=+-@\t\r")


def as_text_cell(value):
    """Return ``value`` so a spreadsheet shows it as text: a string with a formula prefix gets a leading quote."""
    if isinstance(value, str) and value and value[0] in FORMULA_PREFIXES:
        return "'" + value
    return value


class TextCellWriter:

    """``csv.writer`` wrapper that passes every cell through ``as_text_cell``."""

    def __init__(self, f, *args, **kwargs):
        self._writer = csv.writer(f, *args, **kwargs)

    def writerow(self, row):
        return self._writer.writerow([as_text_cell(value) for value in row])

    def writerows(self, rows):
        for row in rows:
            self.writerow(row)


def store_cells_as_text(workbook):
    """Store string cells that openpyxl inferred as formulas as plain strings instead."""
    for worksheet in workbook.worksheets:
        for row in worksheet.iter_rows():
            for cell in row:
                if cell.data_type == "f":
                    cell.data_type = "s"
