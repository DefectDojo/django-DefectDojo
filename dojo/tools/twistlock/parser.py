import csv
import hashlib
import io
import json
import logging
import textwrap
from datetime import datetime

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

        # Parse timestamp information (Item 4)
        published_date = row.get("Published", "")
        discovered_date = row.get("Discovered", "")
        finding_date = None

        # Use Published date as primary, fallback to Discovered
        date_str = published_date or discovered_date
        if date_str:
            try:
                # Handle format like "2020-09-04 00:15:00.000"
                finding_date = datetime.strptime(date_str.split(".")[0], "%Y-%m-%d %H:%M:%S").date()
            except ValueError:
                try:
                    # Handle alternative formats
                    finding_date = datetime.strptime(date_str[:10], "%Y-%m-%d").date()
                except ValueError:
                    logger.warning(f"Could not parse date: {date_str}")

        # Build container/image metadata for impact field (Item 3)
        impact_parts = []

        # Registry and repository information which can change between scans, so we add it to the impact field as the description field is sometimes used for hash code calculation
        registry = row.get("Registry", "")
        repository = row.get("Repository", "")
        tag = row.get("Tag", "")
        image_id = row.get("Id", "")
        distro = row.get("Distro", "")

        if registry:
            impact_parts.append(f"Registry: {registry}")
        if repository:
            impact_parts.append(f"Repository: {repository}")
        if tag:
            impact_parts.append(f"Tag: {tag}")
        if image_id:
            impact_parts.append(f"Image ID: {image_id}")
        if distro:
            impact_parts.append(f"Distribution: {distro}")

        # Host and container information
        hosts = row.get("Hosts", "")
        containers = row.get("Containers", "")
        clusters = row.get("Clusters", "")
        binaries = row.get("Binaries", "")
        custom_labels = row.get("Custom Labels", "")

        if hosts:
            impact_parts.append(f"Hosts: {hosts}")
        if containers:
            impact_parts.append(f"Containers: {containers}")
        if clusters:
            impact_parts.append(f"Clusters: {clusters}")
        if binaries:
            impact_parts.append(f"Binaries: {binaries}")
        if custom_labels:
            impact_parts.append(f"Custom Labels: {custom_labels}")

        # Add timestamp information to impact
        if published_date:
            impact_parts.append(f"Published: {published_date}")
        if discovered_date:
            impact_parts.append(f"Discovered: {discovered_date}")

        impact_text = "\n".join(impact_parts) if impact_parts else data_severity

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
            date=finding_date,
            severity=convert_severity(data_severity),
            description=data_description
            + "\n\nVulnerable Package: "
            + data_package_name
            + "\n\nCurrent Version: "
            + str(data_package_version),
            mitigation=data_fix_status,
            component_name=textwrap.shorten(
                data_package_name, width=200, placeholder="...",
            ),
            component_version=data_package_version,
            severity_justification=f"(CVSS v3 base score: {data_cvss})",
            impact=impact_text,
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
            # Extract image metadata for impact field (Item 3)
            result = tree["results"][0]
            image_metadata = self.build_image_metadata(result)

            # Parse vulnerabilities
            vulnerabilityTree = result.get("vulnerabilities", [])
            for node in vulnerabilityTree:
                item = get_item(node, test, image_metadata)
                unique_key = node["id"] + str(
                    node["packageName"]
                    + str(node["packageVersion"])
                    + str(node["severity"]),
                )
                items[unique_key] = item

            # Parse compliance findings
            complianceTree = result.get("compliances", [])
            for node in complianceTree:
                item = get_compliance_item(node, test, image_metadata)
                # Create unique key for compliance findings - prefer ID if available
                if node.get("id"):
                    unique_key = f"compliance_{node['id']}"
                else:
                    # Fallback to hash of title + description
                    unique_key = "compliance_" + hashlib.md5(
                        (node.get("title", "") + node.get("description", "")).encode("utf-8"),
                        usedforsecurity=False,
                    ).hexdigest()
                items[unique_key] = item
        return list(items.values())

    def build_image_metadata(self, result):
        """Build image metadata string for impact field"""
        metadata_parts = []

        image_id = result.get("id", "")
        distro = result.get("distro", "")

        if image_id:
            metadata_parts.append(f"Image ID: {image_id}")
        if distro:
            metadata_parts.append(f"Distribution: {distro}")

        return "\n".join(metadata_parts)


def get_item(vulnerability, test, image_metadata=""):
    severity = (
        convert_severity(vulnerability["severity"])
        if "severity" in vulnerability
        else "Info"
    )
    cvssv3 = vulnerability.get("vector")
    status = vulnerability.get("status", "There seems to be no fix yet. Please check description field.")
    cvssv3_score = vulnerability.get("cvss")
    riskFactors = vulnerability.get("riskFactors", "No risk factors.")

    # Build impact field combining severity and image metadata which can change between scans, so we add it to the impact field as the description field is sometimes used for hash code calculation
    impact_parts = [severity]
    if image_metadata:
        impact_parts.append(image_metadata)
    impact_text = "\n".join(impact_parts)

    # create the finding object
    finding = Finding(
        title=vulnerability.get("id", "Unknown Vulnerability")
        + ": "
        + vulnerability.get("packageName", "Unknown Package")
        + " - "
        + str(vulnerability.get("packageVersion", "")),
        test=test,
        severity=severity,
        description=vulnerability.get("description", "")
        + "\n\nVulnerable Package: "
        + vulnerability.get("packageName", "")
        + "\n\nCurrent Version: "
        + str(vulnerability.get("packageVersion", "")),
        mitigation=status.title() if isinstance(status, str) else "",
        references=vulnerability.get("link"),
        component_name=vulnerability.get("packageName", ""),
        component_version=vulnerability.get("packageVersion", ""),
        severity_justification=f"Vector: {cvssv3} (CVSS v3 base score: {cvssv3_score})\n\n{riskFactors}",
        cvssv3=cvssv3,
        cvssv3_score=cvssv3_score,
        impact=impact_text,
    )
    finding.unsaved_vulnerability_ids = [vulnerability["id"]] if "id" in vulnerability else None
    finding.description = finding.description.strip()

    return finding


def get_compliance_item(compliance, test, image_metadata=""):
    """Create a Finding object for compliance issues"""
    severity = (
        convert_severity(compliance["severity"])
        if "severity" in compliance
        else "Info"
    )

    title = compliance.get("title", "Unknown Compliance Issue")
    description = compliance.get("description", "No description specified")
    compliance_id = compliance.get("id", "")
    category = compliance.get("category", "")
    layer_time = compliance.get("layerTime", "")

    # Build comprehensive description
    desc_parts = [f"**Compliance Issue:** {title}\n\n"]

    if compliance_id:
        desc_parts.append(f"**Compliance ID:** {compliance_id}\n\n")

    if category:
        desc_parts.append(f"**Category:** {category}\n\n")

    desc_parts.append(f"**Description:** {description}\n\n")

    # Build impact field combining severity and image metadata
    impact_parts = [severity]
    if image_metadata:
        impact_parts.append(image_metadata)
    if layer_time:
        desc_parts.append(f"Layer Time: {layer_time}")
    impact_text = "\n".join(impact_parts)

    # create the finding object for compliance
    finding = Finding(
        title=f"Compliance: {title}",
        test=test,
        severity=severity,
        description="".join(desc_parts),
        mitigation="Review and address the compliance issue as described in the description.",
        severity_justification=f"Compliance severity: {severity}",
        impact=impact_text,
        vuln_id_from_tool=str(compliance_id) if compliance_id else None,
    )
    finding.description = finding.description.strip()

    # Add compliance-specific tags
    tags = ["compliance"]
    if category:
        tags.append(category.lower())
    finding.unsaved_tags = tags

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
