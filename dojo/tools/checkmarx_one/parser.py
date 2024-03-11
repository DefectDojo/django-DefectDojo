import datetime
import json
from dateutil import parser
from dojo.models import Finding


class CheckmarxOneParser(object):
    def get_scan_types(self):
        return ["Checkmarx One Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Checkmarx One Scan"

    def _parse_date(self, value):
        if isinstance(value, str):
            return parser.parse(value)
        elif isinstance(value, dict) and isinstance(value.get("seconds"), int):
            return datetime.datetime.utcfromtimestamp(value.get("seconds"))
        else:
            return None

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        if "vulnerabilities" in data:
            results = data.get("vulnerabilities", [])
            for result in results:
                id = result.get("identifiers")[0].get("value")
                cwe = None
                if 'vulnerabilityDetails' in result:
                    cwe = result.get("vulnerabilites").get("cweId")
                severity = result.get("severity")
                locations_uri = result.get("location").get("file")
                locations_startLine = result.get("location").get("start_line")
                locations_endLine = result.get("location").get("end_line")
                finding = Finding(
                    unique_id_from_tool=id,
                    file_path=locations_uri,
                    title=id + "_" + locations_uri,
                    test=test,
                    cwe=cwe,
                    severity=severity,
                    description="**id**: " + str(id) + "\n"
                    + "**uri**: " + locations_uri + "\n"
                    + "**startLine**: " + str(locations_startLine) + "\n"
                    + "**endLine**: " + str(locations_endLine) + "\n",
                    false_p=False,
                    duplicate=False,
                    out_of_scope=False,
                    static_finding=True,
                    dynamic_finding=False,
                )
                findings.append(finding)
        elif "results" in data:
            results = data.get("results", [])
            for vulnerability in results:
                result_type = vulnerability.get("type")
                date = self._parse_date(vulnerability.get("firstFoundAt"))
                cwe = None
                if 'vulnerabilityDetails' in vulnerability:
                    cwe = vulnerability.get("vulnerabilites", {}).get("cweId")
                if result_type == "sast":
                    descriptionDetails = vulnerability.get("description")
                    file_path = vulnerability.get("data").get("nodes")[0].get("fileName")
                    finding = Finding(
                        description=descriptionDetails,
                        title=descriptionDetails,
                        file_path=file_path,
                        date=date,
                        cwe=cwe,
                        severity=vulnerability.get("severity").title(),
                        test=test,
                        static_finding=True,
                    )
                    if vulnerability.get("id"):
                        finding.unique_id_from_tool = (
                            vulnerability.get("id")
                        )
                    else:
                        finding.unique_id_from_tool = str(
                            vulnerability.get("similarityId")
                        )
                    findings.append(finding)
                if result_type == "kics":
                    description = vulnerability.get("description")
                    file_path = vulnerability.get("data").get("filename")
                    finding = Finding(
                        title=f'{description}',
                        description=description,
                        date=date,
                        cwe=cwe,
                        severity=vulnerability.get("severity").title(),
                        verified=vulnerability.get("state") != "TO_VERIFY",
                        file_path=file_path,
                        test=test,
                        static_finding=True,
                    )
                    if vulnerability.get("id"):
                        finding.unique_id_from_tool = vulnerability.get(
                            "id"
                        )
                    else:
                        finding.unique_id_from_tool = str(
                            vulnerability.get("similarityId")
                        )
                    findings.append(finding)
        return findings
