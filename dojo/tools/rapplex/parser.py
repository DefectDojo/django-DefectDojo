import json
from datetime import datetime

from dojo.models import Endpoint, Finding


class RapplexParser:
    """
    Rapplex - Web Application Security Scanner
    """
    def get_scan_types(self):
        return ["Rapplex Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Rapplex Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import Rapplex JSON report."

    def get_findings(self, file, test):
        raw_data = file.read()
        data = json.loads(raw_data)
        findings = []
        severities = ["Information", "Low", "Medium", "High", "Critical"]

        for severity in severities:
            current_severity = data.get("Severities", {}).get(severity)
            if not current_severity:
                continue

            main_issue_groups = current_severity.get("IssueGroups", [])
            for main_issue_group in main_issue_groups:
                issues = main_issue_group.get("Issues", [])

                for issue in issues:
                    scan_id = data.get("ScanId", "")
                    formatted_date = datetime.strptime(data.get("StartedDate", ""), "%d/%m/%Y %H:%M:%S").strftime("%Y-%m-%d")
                    severity_level = current_severity.get("Name", "")
                    title = issue.get("Title", "")
                    url = issue.get("Url", "")
                    req = issue.get("HttpRequest", "")
                    res = issue.get("HttpResponse", "")
                    vIndex = issue.get("vIndex", "")
                    vuln_id = f"{scan_id}_{vIndex}"  # scanId and vIndex combined to create unique_id_from_tool
                    issue_definition = main_issue_group.get("Definition", {})

                    cwe_val = None
                    for classification in issue_definition.get("Classifications", []):
                        if classification.get("Foundation") == "CWE":
                            cwe_val = classification.get("Value")
                            break

                    reference_texts = []
                    for reference in issue_definition.get("References", []):
                        ref_title = reference.get("Title", "")
                        ref_link = reference.get("Link", "")
                        reference_texts.append(f"{ref_title}\n{ref_link}")  # ref_title and ref_link combined to references section
                    reference_array = "\n".join(reference_texts)

                    desc_rem = issue_definition.get("Sections", {}).get("Remediation", "")
                    desc_sum = issue_definition.get("Sections", {}).get("Summary", "")

                    if (len(desc_rem) > 0):
                        desc_text = f"\n{desc_sum}\nRemediation:\n{desc_rem}"  # summary and remediation combined to create description
                    else:
                        desc_text = desc_sum

                    finding = Finding(
                        title=title,
                        test=test,
                        severity=severity_level,
                        date=formatted_date,
                        description=desc_text,
                        cwe=cwe_val,
                        references=reference_array,
                        unique_id_from_tool=vuln_id,
                    )

                    finding.active = True
                    finding.unsaved_request = req
                    finding.unsaved_response = res

                    endpoint = Endpoint.from_uri(url)
                    finding.unsaved_endpoints.append(endpoint)

                    findings.append(finding)
        return findings
