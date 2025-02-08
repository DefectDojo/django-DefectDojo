import json

from dojo.models import Endpoint, Finding


class LegitifyParser:

    def get_scan_types(self):
        return ["Legitify Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Legitify output file can be imported in JSON format."

    def severity_mapper(self, severity):
        mapping = {
            "LOW": "Low",
            "MEDIUM": "Medium",
            "HIGH": "High",
            "CRITICAL": "Critical",
        }
        return mapping.get(severity, "Low")

    def parse_json(self, file):
        try:
            data = file.read()
            try:
                tree = json.loads(str(data, "utf-8"))
            except Exception:
                tree = json.loads(data)
        except Exception:
            msg = "Invalid format"
            raise ValueError(msg)
        return tree

    def get_findings(self, file, test):
        report_tree = self.parse_json(file)

        findings = []
        for content_key, content_value in report_tree.get("content", {}).items():
            policy_info = content_value.get("policyInfo", {})
            is_finding = False
            endpoints = set()
            references = set()
            for violation in content_value.get("violations", []):
                if violation.get("status", None) == "FAILED":
                    is_finding = True
                    url = violation.get("canonicalLink", None)
                    if url:
                        references.add(url)
                        endpoints.add(Endpoint.from_uri(url))

            if is_finding:
                finding = Finding(
                    description=policy_info.get("description", ""),
                    dynamic_finding=False,
                    impact="\n".join(policy_info.get("threat", [])),
                    mitigation="\n".join(policy_info.get("remediationSteps", [])),
                    references="\n".join(references),
                    severity=self.severity_mapper(policy_info.get("severity", "LOW")),
                    static_finding=True,
                    title=f'{policy_info.get("namespace", "").capitalize()} | {policy_info.get("title", "")}',
                    vuln_id_from_tool=policy_info.get("policyName", None),
                )
                finding.unsaved_endpoints = list(endpoints)
                findings.append(finding)
        return findings
