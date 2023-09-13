import json
from dojo.models import Endpoint, Finding


class DrHeaderParser(object):
    def get_scan_types(self):
        return ["DrHeader JSON Importer"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import DrHeader JSON output."

    @staticmethod
    def _create_finding(test, finding, url=None):
        rule = finding.get("rule")
        value = finding.get("value", "")
        expected = finding.get("expected", [])
        anomalies = finding.get("anomalies", [])
        delimiter = finding.get("delimiter", ", ")

        title = f"Header: {rule}"
        description = [f"{finding['message']}"]

        if url is not None:
            description.append(f"**URL**: {url}")

        if value:
            description.append(f"**Observed**: {value}")

        if expected:
            description.append(f"**Expected**: {delimiter.join(expected)}")

        if anomalies:
            description.append(f"**Anomalies**: {delimiter.join(anomalies)}")

        severity = finding.get("severity").title()

        finding = Finding(
            title=title,
            test=test,
            description="\n".join(description),
            severity=severity,
            active=True,
            verified=True,
            static_finding=False,
        )

        if url is not None:
            finding.unsaved_endpoints = [Endpoint.from_uri(url)]

        return finding

    @staticmethod
    def _parse_json(filename):
        try:
            data = json.load(filename)
        except ValueError:
            data = []  # Workaround for DrHeader invalid json. Issue #8281
        return data

    def get_findings(self, filename, test):
        data = self._parse_json(filename)
        items = []

        # Exit early if data is empty
        if not data:
            return items

        if any("url" in item for item in data):  # Handle bulk reports

            items = [
                self._create_finding(test=test, finding=finding, url=item["url"])
                for item in data
                for finding in item.get("report", [])
            ]
        else:  # Handle single reports
            items = [
                self._create_finding(test=test, finding=finding) for finding in data
            ]

        return items
