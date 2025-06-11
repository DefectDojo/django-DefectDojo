import csv
from abc import ABC, abstractmethod
from django.http import HttpResponse


class BaseReportManager(ABC):
    def __init__(self, findings, user=None):
        self.findings = findings
        self.user = user

    @abstractmethod
    def generate_report(self, attributes=None, excludes=None, foreign_keys=None):
        """Abstract method to generate a report."""
        pass

    def _generate_headers(self, excludes, attributes, foreign_keys):
        headers = []
        for key in dir(self.findings[0]):
            if key not in excludes and not key.startswith("_"):
                headers.append(key)
        headers.extend(attributes)
        headers.extend(foreign_keys)
        return headers

    def _generate_row(self, finding, excludes, attributes, foreign_keys):
        row = []
        for key in dir(finding):
            if key not in excludes and not key.startswith("_"):
                value = getattr(finding, key, None)
                if callable(value):
                    value = value()
                row.append(value)
        for attr in attributes:
            row.append(getattr(finding, attr, ""))
        for fk in foreign_keys:
            fk_value = getattr(finding, fk, None)
            row.append(str(fk_value) if fk_value else "")
        return row


class CSVReportManager(BaseReportManager):
    def generate_report(
        self,
        attributes=None,
        excludes=None,
        foreign_keys=None
    ):
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = "attachment; filename=findings.csv"
        writer = csv.writer(response)

        attributes = attributes or []
        excludes = excludes or []
        foreign_keys = foreign_keys or []

        headers = self._generate_headers(excludes, attributes, foreign_keys)
        writer.writerow(headers)

        # Generar filas de datos
        for finding in self.findings:
            row = self._generate_row(finding, excludes, attributes, foreign_keys)
            writer.writerow(row)

        return response
