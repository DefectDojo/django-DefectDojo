import json

from dojo.models import Finding

RISK_TO_CWE_MAP = {
    "accidental-secret-leak": 200,
    "code-backdooring": 912,
    "container-baseimage-backdooring": 912,
    "container-platform-escape": 1008,
    "cross-site-request-forgery": 352,
    "cross-site-scripting": 79,
    "dos-risky-access-across-trust-boundary": 400,
    "incomplete-model": 1008,
    "ldap-injection": 90,
    "missing-authentication-second-factor": 308,
    "missing-authentication": 306,
    "missing-build-infrastructure": 1127,
    "missing-cloud-hardening": 1008,
    "missing-file-validation": 434,
    "missing-hardening": 16,
    "missing-identity-propagation": 204,
    "missing-identity-provider-isolation": 1008,
    "missing-identity-store": 287,
    "missing-network-segmentation": 1008,
    "missing-vault-isolation": 1008,
    "missing-vault": 522,
    "missing-waf": 1008,
    "mixed-target-on-shared-runtime": 1008,
    "path-traversal": 22,
    "push-instead-of-pull-deployment": 1127,
    "search-query-injection": 74,
    "server-side-request-forgery": 918,
    "service-registry-poisoning": 693,
    "sql-injection-rule": 89,
    "unchecked-deployment": 1127,
    "unencrypted-asset": 311,
    "unencrypted-communication": 319,
    "unguarded-access-from-internet": 501,
    "unguarded-direct-datastore-access": 501,
    "unnecessary-communication-link": 1008,
    "unnecessary-data-asset": 1008,
    "unnecessary-data-transfer": 1008,
    "unnecessary-technical-asset": 1008,
    "untrusted-deserialization": 502,
    "wrong-communication-link": 1008,
    "wrong-trust-boudnary-content": 1008,
    "xml-external-entity": 611
}


class ThreagileParser(object):
    """
    Import ThreaAgile threatmodel risk finding in JSON format
    """

    REQUIRED_FIELDS = ["category", "title", "severity", "synthetic_id", "exploitation_impact"]

    def get_scan_types(self):
        return ["Threagile risks report"]

    def get_label_for_scan_types(self, scan_type):
        return "Threagile risks report"

    def get_description_for_scan_types(self, scan_type):
        return "Threagile Risks Report in JSON format (risks.json)."

    def get_findings(self, file, test):
        if file is None:
            return None

        return self.get_items(json.load(file), test)

    def get_items(self, tree, test):
        if not isinstance(tree, list):
            raise ValueError("Invalid ThreAgile risks file")
        if not tree:
            return list()
        findings = []
        for item in tree:
            for field in self.REQUIRED_FIELDS:
                if field not in item.keys():
                    raise ValueError(f"Invalid ThreAgile risks file, missing field {field}")
            severity = item.get("severity").capitalize()
            severity = severity if severity != "Elevated" else "High"
            finding = Finding(
                title=item.get("category", ""),
                cwe=RISK_TO_CWE_MAP.get(item.get("category"), None),
                description=item.get("title"),
                impact=item.get("exploitation_impact"),
                severity=severity,
                test=test,
                unique_id_from_tool=item.get("synthetic_id")
            )
            self.determine_mitigated(finding, item)
            self.determine_accepted(finding, item)
            self.determine_under_review(finding, item)
            self.determine_false_positive(finding, item)
            self.determine_verified(finding, item)
            findings.append(finding)
        return findings

    def determine_mitigated(self, finding, item):
        risk_status = item.get("risk_status", "unchecked")
        if risk_status == "mitigated":
            finding.is_mitigated = True

    def determine_accepted(self, finding, item):
        risk_status = item.get("risk_status", "unchecked")
        if risk_status == "accepted":
            finding.risk_accepted = True

    def determine_under_review(self, finding, item):
        risk_status = item.get("risk_status", "unchecked")
        if risk_status == "in-discussion":
            finding.under_review = True

    def determine_false_positive(self, finding, item):
        risk_status = item.get("risk_status", "unchecked")
        if risk_status == "false-positive":
            finding.false_p = True

    def determine_verified(self, finding, item):
        risk_status = item.get("risk_status", "unchecked")
        if risk_status == "in-progress":
            finding.verified = True
