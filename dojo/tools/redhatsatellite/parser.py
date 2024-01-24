import json
from datetime import datetime

from dojo.models import Endpoint, Finding


class RedHatSatelliteParser(object):
    def get_scan_types(self):
        return ["Red Hat Satellite"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "JSON Output of Red Hat Satellite."

    def severity_mapping(self, input):
        if input == "Critical":
            severity = "Critical"
        elif input == "Important":
            severity = "High"
        elif input == "Moderate":
            severity = "Medium"
        elif input == "Low":
            severity = "Low"
        else:
            severity = "Low"
        return severity

    def get_findings(self, filename, test):
        findings = list()
        tree = filename.read()
        try:
            data = json.loads(str(tree, "utf-8"))
        except Exception:
            data = json.loads(tree)
        for result in data["results"]:
            id = result.get("id", None)
            pulp_id = result.get("pulp_id", None)
            title = result.get("title", None)
            errata_id = result.get("errata_id", None)
            severity = result.get("severity", None)
            description = result.get("description", None)
            solution = result.get("solution", None)
            summary = result.get("summary", None)
            reboot_suggested = result.get("reboot_suggested", None)
            uuid = result.get("uuid", None)
            name = result.get("name", None)
            type = result.get("type", None)
            cves = result.get("cves", None)
            bugs = result.get("bugs", None)
            hosts_available_count = result.get("hosts_available_count", None)
            hosts_applicable_count = result.get("hosts_applicable_count", None)
            packages = result.get("packages", None)
            module_streams = result.get("module_streams", None)
            installable = result.get("installable", None)
            
            find = Finding(
                title=title,
                test=test,
                description=description,
                severity=self.severity_mapping(input=severity),
                mitigation=solution,
                # impact=impact,
                # references=references,
                dynamic_finding=True,
            )
            findings.append(find)
            
        return findings
