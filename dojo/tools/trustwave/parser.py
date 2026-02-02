import csv
import hashlib
import io

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.url.models import URL


class TrustwaveParser:
    def get_scan_types(self):
        return ["Trustwave Scan (CSV)"]

    def get_label_for_scan_types(self, scan_type):
        return "Trustwave Scan (CSV)"

    def get_description_for_scan_types(self, scan_type):
        return "CSV output of Trustwave vulnerability scan."

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        reader = csv.DictReader(
            io.StringIO(content), delimiter=",", quotechar='"',
        )

        severity_mapping = {
            "I": "Info",
            "L": "Low",
            "M": "Medium",
            "H": "High",
            "C": "Critical",
        }

        dupes = {}
        for row in reader:
            finding = Finding(
                test=test,
                nb_occurences=1,
            )
            host = row.get("Domain")
            if host is None or not host:
                host = row.get("IP")
            port = int(row.get("Port", "") or "0") or ""
            protocol = row.get("Protocol", "")
            if settings.V3_FEATURE_LOCATIONS:
                finding.unsaved_locations = [URL(host=host, port=port, protocol=protocol)]
            else:
                # TODO: Delete this after the move to Locations
                finding.unsaved_endpoints = [Endpoint(host=host, port=port, protocol=protocol)]
            finding.title = row["Vulnerability Name"]
            finding.description = row["Description"]
            finding.references = row.get("Evidence")
            finding.mitigation = row.get("Remediation")

            # manage severity
            finding.severity = severity_mapping.get(row["Severity"], "Low")
            finding.unsaved_vulnerability_ids = [row.get("CVE")]

            dupes_key = hashlib.sha256(
                f"{finding.severity}|{finding.title}|{finding.description}".encode(),
            ).hexdigest()

            if dupes_key in dupes:
                dupes[dupes_key].nb_occurences += 1
            else:
                dupes[dupes_key] = finding

        return list(dupes.values())
