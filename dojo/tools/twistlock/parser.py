import csv
import hashlib
import io
import json
import logging
import textwrap
import dateutil

from dojo.models import Finding
from django.conf import settings
from functools import reduce

logger = logging.getLogger(__name__)


class TwistlockCSVParser:
    def parse_issue(self, row, test):
        if not row:
            return None

        data_vulnerability_id = row.get("CVE ID", "")
        data_package_version = row.get("Package Version", "")
        data_fix_status = row.get("Fix Status", "")
        data_package_name = row.get("Source Package", "")
        row.get("Id", "")
        data_severity = row.get("Severity", "")
        data_cvss = row.get("CVSS", "")
        data_description = row.get("Description", "")
        data_tag = row.get("Tag", "")
        data_type = row.get("Type")
        data_package_version = row.get("Package Version", "")
        data_package_license = row.get("Package License", "")
        data_package_name = row.get("Package Name", "")
        data_cluster = row.get("Clusters", "")
        data_namespaces = row.get("Namespaces", "")
        data_package_path = row.get("Package Path", "")
        data_name = row.get("Name", "")
        data_cloud_id = row.get("Id", "")
        data_runtime = row.get("Runtime", "")
        data_cause = row.get("Cause", "")
        data_found_in = row.get("Found In", "")
        data_purl = row.get("PURL", "")
        data_risk_factors = row.get("Risk Factors", "")

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
            data_description_complete = reduce(
                lambda str, kv: str.replace(kv[0], kv[1]),
                settings.DD_INVALID_ESCAPE_STR.items(),
                data_description,
            )
            title = data_description_complete

        finding = Finding(
            title=textwrap.shorten(title, width=255, placeholder="..."),
            test=test,
            severity=convert_severity(data_severity),
            description= self.get_description(data_description
                                            , data_type
                                            , data_tag
                                            , data_cluster
                                            , data_namespaces
                                            , data_package_name
                                            , data_package_license
                                            , data_package_version
                                            , data_package_path
                                            , data_name
                                            , data_cloud_id
                                            , data_runtime
                                            , data_cause
                                            , data_found_in
                                            , data_purl
                                            , data_risk_factors),
            mitigation=data_fix_status,
            references=row.get("Vulnerability Link", ""),
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
            vuln_id_from_tool= data_vulnerability_id,
            publish_date=dateutil.parser.parse(row.get('Published')) if row.get('Published', None) else None,
        )
        finding.unsaved_tags = [row.get('Custom Tag') if row.get('Custom Tag', None) else settings.DD_CUSTOM_TAG_PARSER.get("twistlock")]
        finding.description = finding.description.strip()
        if data_vulnerability_id:
            finding.unsaved_vulnerability_ids = [data_vulnerability_id]

        return finding

    def get_description(self,
                        data_description,
                        data_type,
                        data_tag,
                        data_cluster,
                        data_namespaces,
                        data_package_name,
                        data_package_license,
                        data_package_version,
                        data_package_path,
                        data_name,
                        data_cloud_id,
                        data_runtime,
                        data_cause,
                        data_found_in,
                        data_purl,
                        data_risk_factors):
        return "<p><strong>Description:</strong> " \
                + data_description \
                + "</p><p><strong>Type:</strong> " \
                + str(data_type) \
                + "</p><p><strong>Tag:</strong> " \
                + str(data_tag) \
                + "</p><p><strong>Cluster:</strong> " \
                + str(data_cluster) \
                + "</p><p><strong>Namespaces:</strong> " \
                + str(data_namespaces) \
                + "</p><p><strong>Vulnerable Package:</strong> " \
                + str(data_package_name) \
                + "</p><p><strong>Vulnerable Package License:</strong> " \
                + str(data_package_license) \
                + "</p><p><strong>Current Version:</strong> " \
                + str(data_package_version) \
                + "</p><p><strong>Package path:</strong> " \
                + str(data_package_path) \
                + "</p>" \
                + "</p><p><strong>Name:</strong> " \
                + str(data_name) \
                + "</p>" \
                + "</p><p><strong>Cloud Id:</strong> " \
                + str(data_cloud_id) \
                + "</p>" \
                + "</p><p><strong>Runtime:</strong> " \
                + str(data_runtime) \
                + "</p>" \
                + "</p><p><strong>Risk Factors:</strong> " \
                + str(data_risk_factors) \
                + "</p>" \
                + "</p><p><strong>Cause:</strong> " \
                + str(data_cause) \
                + "</p>" \
                + "</p><p><strong>Found In:</strong> " \
                + str(data_found_in) \
                + "</p>" \
                + "</p><p><strong>PURL:</strong> " \
                + str(data_purl) \
                + "</p>"

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
                    ).encode("utf-8"),
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
            baseImage = tree.get("baseImage", "")
            for node in vulnerabilityTree:
                item = get_item(node, test, baseImage)
                unique_key = node["id"] + str(
                    node["packageName"]
                    + str(node["packageVersion"])
                    + str(node["severity"]),
                )
                items[unique_key] = item
        return list(items.values())


def get_item(vulnerability, test, baseImage):
    severity = (
        convert_severity(vulnerability["severity"])
        if "severity" in vulnerability
        else "Info"
    )
    vector = (
        vulnerability["vector"]
        if "vector" in vulnerability
        else "CVSS vector not provided. "
    )
    status = (
        vulnerability["status"]
        if "status" in vulnerability
        else "There seems to be no fix yet. Please check description field."
    )
    cvss = (
        vulnerability["cvss"]
        if "cvss" in vulnerability
        else "No CVSS score yet."
    )
    riskFactors = (
        vulnerability["riskFactors"]
        if "riskFactors" in vulnerability
        else "No risk factors."
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
        description=vulnerability.get("description", "")
        + "<p> Vulnerable Package: "
        + vulnerability["packageName"]
        + "</p><p> Current Version: "
        + str(vulnerability["packageVersion"])
        + "</p>"
        + "<p> Base Image: "
        + baseImage,
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
        vuln_id_from_tool= vulnerability['id'],
        publish_date=dateutil.parser.parse(vulnerability.get('publishedDate')) if vulnerability.get('publishedDate', None) else None,

    )
    finding.unsaved_tags = [vulnerability['customTag'] if vulnerability.get('customTag', None) else settings.DD_CUSTOM_TAG_PARSER.get("twistlock")]
    finding.unsaved_vulnerability_ids = [vulnerability["id"]]
    finding.description = finding.description.strip()

    return finding


def convert_severity(severity):
    if severity.lower() == "important":
        return "High"
    if severity.lower() == "moderate":
        return "Medium"
    if severity.lower() == "unimportant":
        return "Low"
    if severity.lower() == "unassigned":
        return "Low"
    if severity.lower() == "negligible":
        return "Low"
    if severity.lower() == "not yet assigned":
        return "Low"
    if severity.lower() == "information":
        return "Info"
    if severity.lower() == "informational":
        return "Info"
    if severity == "":
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
