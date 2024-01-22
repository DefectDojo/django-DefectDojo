import csv
import io
import logging
import re
from datetime import datetime
from django.conf import settings

from dojo.models import Endpoint, Finding

_logger = logging.getLogger(__name__)


def parse_csv(csv_file) -> [Finding]:
    """
    Parses Qualys Report in CSV format
    Args:
        csv_file:
    Returns:
    """

    content = csv_file.read()
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    csv_reader = csv.DictReader(
        io.StringIO(content), delimiter=",", quotechar='"'
    )

    report_findings = get_report_findings(csv_reader)
    dojo_findings = build_findings_from_dict(report_findings)

    return dojo_findings


def get_report_findings(csv_reader) -> [dict]:
    """
    Filters out the unneeded information at the beginning of the Qualys CSV report.
    Args:
        csv_reader:

    Returns:

    """

    report_findings = []

    for row in csv_reader:
        if row.get("Title") and row["Title"] != "Title":
            report_findings.append(row)
        elif row.get("VULN TITLE"):
            report_findings.append(row)
    return report_findings


def _extract_cvss_vectors(cvss_base, cvss_temporal):
    """
    Parses the CVSS3 Vectors from the CVSS3 Base and CVSS3 Temporal fields and returns as a single string.

    This is done because the raw values come with additional characters that cannot be parsed with the cvss library.
        Example: 6.7 (AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H)
    Args:
        cvss_base:
        cvss_temporal:
    Returns:
        A CVSS3 Vector including both Base and Temporal if available
    """

    vector_pattern = r"^\d{1,2}.\d \((.*)\)"
    cvss_vector = "CVSS:3.0/"

    if cvss_base:
        try:
            cvss_vector += re.search(vector_pattern, cvss_base).group(1)
        except IndexError:
            _logger.error(f"CVSS3 Base Vector not found in {cvss_base}")
        except AttributeError:
            _logger.error(f"CVSS3 Base Vector not found in {cvss_base}")
        if cvss_temporal:
            try:
                cvss_temporal_vector = re.search(
                    vector_pattern, cvss_temporal
                ).group(1)
                cvss_vector += "/"
                cvss_vector += cvss_temporal_vector
            except IndexError:
                _logger.error(
                    f"CVSS3 Temporal Vector not found in {cvss_base}"
                )
            except AttributeError:
                _logger.error(
                    f"CVSS3 Temporal Vector not found in {cvss_base}"
                )

        return cvss_vector


def build_findings_from_dict(report_findings: [dict]) -> [Finding]:
    """
    Takes a list of Dictionaries built from CSV and creates a Finding object
    Args:
        report_findings:
    Returns:

    """
    severity_lookup = {
        "1": "Info",
        "2": "Low",
        "3": "Medium",
        "4": "High",
        "5": "Critical",
    }
    dojo_findings = []
    for report_finding in report_findings:
        if report_finding.get("FQDN"):
            endpoint = Endpoint.from_uri(report_finding.get("FQDN"))
        elif report_finding.get("DNS"):
            endpoint = Endpoint(host=report_finding.get("DNS"))
        else:
            endpoint = Endpoint(host=report_finding["IP"])

        if "CVSS3 Base" in report_finding:
            cvssv3 = _extract_cvss_vectors(
                        report_finding["CVSS3 Base"], report_finding["CVSS3 Temporal"]
                    )
        elif "CVSS3.1 Base" in report_finding:
            cvssv3 = _extract_cvss_vectors(
                        report_finding["CVSS3.1 Base"], report_finding["CVSS3.1 Temporal"]
                    )
        # Get the date based on the first_seen setting
        try:
            if settings.USE_FIRST_SEEN:
                if date := report_finding.get("First Detected"):
                    date = datetime.strptime(date, "%m/%d/%Y %H:%M:%S").date()
            else:
                if date := report_finding.get("Last Detected"):
                    date = datetime.strptime(date, "%m/%d/%Y %H:%M:%S").date()
        except Exception:
            date = None

        finding_with_id = next((obj for obj in dojo_findings if obj.vuln_id_from_tool == report_finding["QID"]), None)
        if finding_with_id:
            finding = finding_with_id
        else:
            if report_finding.get("Title"):
                finding = Finding(
                    title=f"QID-{report_finding['QID']} | {report_finding['Title']}",
                    mitigation=report_finding["Solution"],
                    description=f"{report_finding['Threat']}\nResult Evidence: \n{report_finding.get('Threat', 'Not available')}",
                    severity=severity_lookup.get(report_finding["Severity"], "Info"),
                    impact=report_finding["Impact"],
                    date=date,
                    vuln_id_from_tool=report_finding["QID"],
                    cvssv3=cvssv3
                )
                cve_data = report_finding.get("CVE ID")
                # Qualys reports regression findings as active, but with a Date Last
                # Fixed.
                if report_finding["Date Last Fixed"]:
                    finding.mitigated = datetime.strptime(
                        report_finding["Date Last Fixed"], "%m/%d/%Y %H:%M:%S"
                    )
                    finding.is_mitigated = True
                else:
                    finding.is_mitigated = False

                finding.active = report_finding["Vuln Status"] in (
                    "Active",
                    "Re-Opened",
                    "New",
                )

                if finding.active:
                    finding.mitigated = None
                    finding.is_mitigated = False
            elif report_finding.get("VULN TITLE"):
                # Get the date based on the first_seen setting
                try:
                    if settings.USE_FIRST_SEEN:
                        if date := report_finding.get("LAST SCAN"):
                            date = parser.parse(date.replace("Z", ""))
                    else:
                        if date := report_finding.get("LAST SCAN"):
                            date = parser.parse(date.replace("Z", ""))
                except Exception:
                    date = None

                finding = Finding(
                    title=f"QID-{report_finding['QID']} | {report_finding['VULN TITLE']}",
                    mitigation=report_finding["SOLUTION"],
                    description=f"{report_finding['THREAT']}\nResult Evidence: \n{report_finding.get('THREAT', 'Not available')}",
                    severity=report_finding["SEVERITY"],
                    impact=report_finding["IMPACT"],
                    date=date,
                    vuln_id_from_tool=report_finding["QID"]
                )
                cve_data = report_finding.get("CVEID")

        finding.unsaved_vulnerability_ids = (
            cve_data.split(",") if "," in cve_data else [cve_data]
        )
        finding.verified = True
        finding.unsaved_endpoints.append(endpoint)
        if not finding_with_id:
            dojo_findings.append(finding)
    return dojo_findings
