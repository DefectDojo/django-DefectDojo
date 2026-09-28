import csv
import hashlib
import io

from cvss import parser as cvss_parser
from dateutil.parser import parse

from dojo.finding.cwe import cwe_number, parse_cwes
from dojo.location.feature import locations_enabled
from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData


class GenericCSVParser:
    ID = "Generic Findings Import"

    def _get_findings_csv(self, filename):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        reader = csv.DictReader(
            io.StringIO(content), delimiter=",", quotechar='"',
        )

        dupes = {}
        for row in reader:
            finding = Finding(
                title=row["Title"],
                description=row["Description"],
                date=parse(row["Date"]).date(),
                severity=self.get_severity(row["Severity"]),
                duplicate=self._convert_bool(
                    row.get("Duplicate", "FALSE"),
                ),  # bool False by default
                nb_occurences=1,
            )
            # manage active
            if "Active" in row:
                finding.active = self._convert_bool(row.get("Active"))
            if "IsMitigated" in row:
                finding.is_mitigated = self._convert_bool(row.get("IsMitigated"))
            if mitigated_date := self._cell(row, "MitigatedDate"):
                finding.mitigated = parse(mitigated_date)
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
            if row.get("Vulnerability Id"):
                if finding.unsaved_vulnerability_ids:
                    finding.unsaved_vulnerability_ids.append(
                        row["Vulnerability Id"],
                    )
                else:
                    finding.unsaved_vulnerability_ids = [
                        row["Vulnerability Id"],
                    ]
            # manage CWE
            if cwe_id := self._cell(row, "CweId"):
                finding.cwe = int(cwe_id)
            # manage multiple CWEs (comma/space separated column), keeping the
            # primary on finding.cwe; the full set is persisted via unsaved_cwes.
            if row.get("CweIds"):
                cwes = parse_cwes(row["CweIds"])
                if cwes:
                    if not finding.cwe:
                        finding.cwe = cwe_number(cwes[0])
                    finding.unsaved_cwes = cwes

            if epss_score := self._cell(row, "epss_score"):
                finding.epss_score = float(epss_score)

            if epss_percentile := self._cell(row, "epss_percentile"):
                finding.epss_percentile = float(epss_percentile)

            if "CVSSV3" in row:
                cvss_objects = cvss_parser.parse_cvss_from_text(row["CVSSV3"])
                if len(cvss_objects) > 0:
                    finding.cvssv3 = cvss_objects[0].clean_vector()

            # Finding.save() recalculates the score from a valid CVSSV3 vector, so this
            # value only survives when the report has a score without a vector
            if cvssv3_score := self._cell(row, "CVSSV3_score"):
                finding.cvssv3_score = float(cvssv3_score)

            if "CVSSV4" in row:
                cvss4_objects = cvss_parser.parse_cvss_from_text(row["CVSSV4"])
                if len(cvss4_objects) > 0:
                    finding.cvssv4 = cvss4_objects[0].clean_vector()

            if cvssv4_score := self._cell(row, "CVSSV4_score"):
                finding.cvssv4_score = float(cvssv4_score)

            if kev_date := self._cell(row, "kev_date"):
                finding.kev_date = parse(kev_date)

            # an empty cell leaves the model default in place (False, False, None)
            for field in ("known_exploited", "ransomware_used", "fix_available"):
                if value := self._cell(row, field):
                    setattr(finding, field, self._convert_bool(value))

            if "fix_version" in row:
                finding.fix_version = row["fix_version"]

            # manage endpoints
            if row.get("Url"):
                if locations_enabled():
                    finding.unsaved_locations = [
                        LocationData.url(url=row["Url"]) if "://" in row["Url"] else LocationData.url(url="//" + row["Url"]),
                    ]
                else:
                    # TODO: Delete this after the move to Locations
                    finding.unsaved_endpoints = [
                        Endpoint.from_uri(row["Url"])
                        if "://" in row["Url"]
                        else Endpoint.from_uri("//" + row["Url"]),
                    ]

            # manage internal de-duplication
            key = hashlib.sha256(
                f"{finding.severity}|{finding.title}|{finding.description}".encode(),
            ).hexdigest()
            if key in dupes:
                find = dupes[key]
                if locations_enabled():
                    find.unsaved_locations.extend(finding.unsaved_locations)
                else:
                    # TODO: Delete this after the move to Locations
                    find.unsaved_endpoints.extend(finding.unsaved_endpoints)
                if find.unsaved_vulnerability_ids:
                    find.unsaved_vulnerability_ids.extend(
                        finding.unsaved_vulnerability_ids,
                    )
                else:
                    find.unsaved_vulnerability_ids = (
                        finding.unsaved_vulnerability_ids
                    )
                if finding.unsaved_cwes:
                    if find.unsaved_cwes:
                        find.unsaved_cwes.extend(finding.unsaved_cwes)
                    else:
                        find.unsaved_cwes = finding.unsaved_cwes
                find.nb_occurences += 1
            else:
                dupes[key] = finding
        return list(dupes.values())

    def _cell(self, row, column):
        """Return the stripped value of a column, or None when the column is absent or the cell is empty."""
        value = row.get(column)
        if value is None:
            return None
        return value.strip() or None

    def _convert_bool(self, val):
        return val.lower()[0:1] == "t"  # bool False by default

    def get_severity(self, severity_input):
        if severity_input in {"Info", "Low", "Medium", "High", "Critical"}:
            return severity_input
        return "Info"
