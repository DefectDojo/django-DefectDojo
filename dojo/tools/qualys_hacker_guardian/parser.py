import csv
import io

from dateutil import parser as date_parser

from dojo.models import Endpoint, Finding


class QualysHackerGuardianParser:

    """Parser for Qualys HackerGuardian"""

    # Severity mapping taken from
    # https://qualysguard.qg2.apps.qualys.com/portal-help/en/malware/knowledgebase/severity_levels.htm
    qualys_severity_lookup = {
        "1": "Low",
        "2": "Low",
        "3": "Medium",
        "4": "High",
        "5": "High",
    }

    def get_scan_types(self):
        return ["Qualys Hacker Guardian Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Qualys Hacker Guardian Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Qualys Hacker Guardian report file can be imported in CSV format."

    def get_endpoint(self, row):
        host = row.get("HOSTNAME", row.get("IP"))
        if (port := row.get("PORT")) is not None:
            host += f":{port}"
        if (protocol := row.get("PROTOCOL")) is not None:
            host = f"{protocol}://{host}"

        return host

    def get_findings(self, filename, test):
        if filename is None:
            return ()
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        reader = csv.DictReader(io.StringIO(content), delimiter=",", quotechar='"')
        dupes = {}
        for row in reader:
            endpoint = Endpoint.from_uri(self.get_endpoint(row))
            finding = Finding(
                title=row.get("VULN TITLE"),
                severity=self.qualys_severity_lookup[row.get("Q_SEVERITY", 1)],
                description=(
                    f'**Category**: {row.get("CATEGORY", "Unknown")}\n'
                    f'**Threat**: {row.get("THREAT", "No threat detected")}\n'
                    f'**Result**: {row.get("RESULT", "No threat detected")}\n'
                ),
                date=date_parser.parse(row.get("LAST SCAN")),
                impact=row.get("IMPACT"),
                mitigation=row.get("SOLUTION"),
                unique_id_from_tool=row.get("QID"),
                dynamic_finding=True,
                active=True,
                nb_occurences=1,
            )
            finding.unsaved_endpoints.append(endpoint)

            dupe_key = finding.unique_id_from_tool
            if dupe_key in dupes:
                finding = dupes[dupe_key]
                if endpoint not in finding.unsaved_endpoints:
                    finding.unsaved_endpoints.append(endpoint)
                finding.nb_occurences += 1
            else:
                dupes[dupe_key] = finding

        return list(dupes.values())
