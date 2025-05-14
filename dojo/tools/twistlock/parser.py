import csv
import hashlib
import io
import json
import logging
import textwrap

from dojo.models import Finding

logger = logging.getLogger(__name__)


class TwistlockCSVParser:
    def parse_issue(self, row, test):
        if not row:
            return None

        data_vulnerability_id = row.get("CVE ID", "")
        data_package_version = row.get("Package Version", "")
        data_fix_status = row.get("Fix Status", "")
        data_package_name = row.get("Packages", "")
        row.get("Id", "")
        data_severity = row.get("Severity", "")
        data_cvss = row.get("CVSS", "")
        data_description = row.get("Description", "")

        if data_vulnerability_id and data_package_name:
            title = (
                data_vulnerability_id
                + ": "
                + data_package_name
                + " - "
                + data_package_version
            )
        elif data_package_name and data_package_version:
            title = data_package_name + " - " + data_package_version
        else:
            title = data_description

        finding = Finding(
            title=textwrap.shorten(title, width=255, placeholder="..."),
            test=test,
            severity=convert_severity(data_severity),
            description=data_description
            + "<p> Vulnerable Package: "
            + data_package_name
            + "</p><p> Current Version: "
            + str(data_package_version)
            + "</p>",
            mitigation=data_fix_status,
            component_name=textwrap.shorten(
                data_package_name, width=200, placeholder="...",
            ),
            component_version=data_package_version,
            false_p=False,
            duplicate=False,
            out_of_scope=False,
            mitigated=None,
            severity_justification=f"(CVSS v3 base score: {data_cvss})",
            impact=data_severity,
        )
        finding.description = finding.description.strip()
        if data_vulnerability_id:
            finding.unsaved_vulnerability_ids = [data_vulnerability_id]

        return finding

    def parse(self, filename, test):
        if filename is None:
            return None
        content = filename.read()
        dupes = {}
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        reader = csv.DictReader(
            io.StringIO(content), delimiter=",", quotechar='"',
        )
        for row in reader:
            finding = self.parse_issue(row, test)
            if finding is not None:
                key = hashlib.md5(
                    (
                        finding.severity
                        + "|"
                        + finding.title
                        + "|"
                        + finding.description
                    ).encode("utf-8"), usedforsecurity=False,
                ).hexdigest()
                if key not in dupes:
                    dupes[key] = finding
        return list(dupes.values())


class TwistlockJsonParser:
    def parse(self, json_output, test):
        tree = self.parse_json(json_output)
        items = []
        if tree:
            items = list(self.get_items(tree, test))
        return items

    def parse_json(self, json_output):
        try:
            data = json_output.read()
            try:
                tree = json.loads(str(data, "utf-8"))
            except Exception:
                tree = json.loads(data)
        except Exception:
            msg = "Invalid format"
            raise ValueError(msg)

        return tree

    def get_items(self, tree, test):
        items = {}
        if "results" in tree:
            vulnerabilityTree = tree["results"][0].get("vulnerabilities", [])
            for node in vulnerabilityTree:
                item = get_item(node, test)
                unique_key = node["id"] + str(
                    node["packageName"]
                    + str(node["packageVersion"])
                    + str(node["severity"]),
                )
                items[unique_key] = item
        return list(items.values())


def get_item(vulnerability, test):
    severity = (
        convert_severity(vulnerability["severity"])
        if "severity" in vulnerability
        else "Info"
    )
    vector = (
        vulnerability.get("vector", "CVSS vector not provided. ")
    )
    status = (
        vulnerability.get("status", "There seems to be no fix yet. Please check description field.")
    )
    cvss = (
        vulnerability.get("cvss", "No CVSS score yet.")
    )
    riskFactors = (
        vulnerability.get("riskFactors", "No risk factors.")
    )

    # create the finding object
    finding = Finding(
        title=vulnerability["id"]
        + ": "
        + vulnerability["packageName"]
        + " - "
        + vulnerability["packageVersion"],
        test=test,
        severity=severity,
        description=vulnerability["description"]
        + "<p> Vulnerable Package: "
        + vulnerability["packageName"]
        + "</p><p> Current Version: "
        + str(vulnerability["packageVersion"])
        + "</p>",
        mitigation=status.title(),
        references=vulnerability.get("link"),
        component_name=vulnerability["packageName"],
        component_version=vulnerability["packageVersion"],
        false_p=False,
        duplicate=False,
        out_of_scope=False,
        mitigated=None,
        severity_justification=f"{vector} (CVSS v3 base score: {cvss})\n\n{riskFactors}",
        impact=severity,
    )
    finding.unsaved_vulnerability_ids = [vulnerability["id"]]
    finding.description = finding.description.strip()

    return finding


def convert_severity(severity):
    if severity.lower() == "important":
        return "High"
    if severity.lower() == "moderate":
        return "Medium"
    if severity.lower() in {"information", "informational", ""}:
        return "Info"
    return severity.title()


class TwistlockParser:
    def get_scan_types(self):
        return ["Twistlock Image Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Twistlock Image Scan"

    def get_description_for_scan_types(self, scan_type):
        return "JSON output of twistcli image scan or CSV."

    def get_findings(self, filename, test):
        if filename is None:
            return []

        if filename.name.lower().endswith(".json"):
            return TwistlockJsonParser().parse(filename, test)
        if filename.name.lower().endswith(".csv"):
            return TwistlockCSVParser().parse(filename, test)
        msg = "Unknown File Format"
        raise ValueError(msg)
