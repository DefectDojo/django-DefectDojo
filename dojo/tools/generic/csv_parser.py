import csv
import hashlib
import io
import logging

from cvss import parser as cvss_parser
from dateutil.parser import parse
from dojo.models import Endpoint, Finding

logger = logging.getLogger(__name__)


class GenericCSVParser:
    ID = "Generic Findings Import"

    def _get_findings_csv(self, filename, **kwargs):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        reader = csv.DictReader(
            io.StringIO(content), delimiter=",", quotechar='"'
        )

        dupes = {}
        for row in reader:
            finding = Finding(
                title=row["Title"],
                description=row["Description"],
                date=parse(row["Date"]).date(),
                severity=self.get_severity(row["Severity"]),
                duplicate=self._convert_bool(
                    row.get("Duplicate", "FALSE")
                ),  # bool False by default
                nb_occurences=1,
            )
            # manage active
            if "Active" in row:
                finding.active = self._convert_bool(row.get("Active"))
            # manage mitigation
            if "Mitigation" in row:
                finding.mitigation = row["Mitigation"]
            # manage impact
            if "Impact" in row:
                finding.impact = row["Impact"]
            # manage impact
            if "References" in row:
                finding.references = row["References"]
            # manage verified
            if "Verified" in row:
                finding.verified = self._convert_bool(row.get("Verified"))
            # manage false positives
            if "FalsePositive" in row:
                finding.false_p = self._convert_bool(row.get("FalsePositive"))
            # manage CVE
            if "CVE" in row and [row["CVE"]]:
                finding.unsaved_vulnerability_ids = [row["CVE"]]
            # manage Vulnerability Id
            if "Vulnerability Id" in row and row["Vulnerability Id"]:
                if finding.unsaved_vulnerability_ids:
                    finding.unsaved_vulnerability_ids.append(
                        row["Vulnerability Id"]
                    )
                else:
                    finding.unsaved_vulnerability_ids = [
                        row["Vulnerability Id"]
                    ]
            # manage CWE
            if "CweId" in row:
                finding.cwe = int(row["CweId"])

            if "CVSSV3" in row:
                cvss_objects = cvss_parser.parse_cvss_from_text(row["CVSSV3"])
                if len(cvss_objects) > 0:
                    finding.cvssv3 = cvss_objects[0].clean_vector()

            # manage endpoints
            if "Url" in row:
                finding.unsaved_endpoints = [
                    Endpoint.from_uri(row["Url"])
                    if "://" in row["Url"]
                    else Endpoint.from_uri("//" + row["Url"])
                ]

            # custom report field mapping
            custom_fields_mapping = kwargs.get('custom_fields_mapping', None)
            if custom_fields_mapping and isinstance(custom_fields_mapping, dict):
                extracted_custom_fields = {}
                for custom_field, report_column in custom_fields_mapping.items():
                    if not custom_field or not report_column:
                        logger.warning(
                            f"custom_fields_mapping contains empty key or value: {custom_fields_mapping}"
                        )
                        continue

                    if report_column in row:
                        extracted_custom_fields[custom_field] = row[report_column]

                # write extracted custom fields dict into finding
                if len(extracted_custom_fields) > 0:
                    finding.custom_fields = extracted_custom_fields

            # manage internal de-duplication
            key = hashlib.sha256(
                f"{finding.severity}|{finding.title}|{finding.description}".encode()
            ).hexdigest()
            if key in dupes:
                find = dupes[key]
                find.unsaved_endpoints.extend(finding.unsaved_endpoints)
                if find.unsaved_vulnerability_ids:
                    find.unsaved_vulnerability_ids.extend(
                        finding.unsaved_vulnerability_ids
                    )
                else:
                    find.unsaved_vulnerability_ids = (
                        finding.unsaved_vulnerability_ids
                    )
                find.nb_occurences += 1
            else:
                dupes[key] = finding
        return list(dupes.values())

    def _convert_bool(self, val):
        return val.lower()[0:1] == "t"  # bool False by default

    def get_severity(self, input):
        if input in ["Info", "Low", "Medium", "High", "Critical"]:
            return input
        else:
            return "Info"
