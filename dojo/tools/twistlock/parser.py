import csv
import hashlib
import io
import json
import logging
import textwrap
import dateutil
import base64
from datetime import datetime

from dojo.models import Finding
from django.conf import settings
from functools import reduce
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


class TwistlockCSVParser:
    def parse_issue(self, row, test):
        if not row:
            return None

        data_vulnerability_id = row.get("CVE ID", "")
        data_package_version = row.get("Package Version", "")
        data_fix_status = row.get("Fix Status", "")
        if row.get("Source Package", "") == "":
            data_package_name = row.get("Packages", "")
        else:
            data_package_name = row.get("Source Package", "")

        data_severity = row.get("Severity", "")
        data_cvss = row.get("CVSS", "")
        data_description = row.get("Description", "")
        data_tag = row.get("Tag", "")
        data_type = row.get("Type")
        data_package_license = row.get("Package License", "")
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
        data_hostname = row.get("Hostname", "")
        data_distro = row.get("Distro", "")
        data_compliance_id = row.get("Compliance ID", "")
        data_result = row.get("Result", "")
        data_packages = row.get("Packages", "")
        data_source_package = row.get("Source Package", "")
        data_published = row.get("Published", "")
        data_services = row.get("Services", "")
        data_vulnerability_link = row.get("Vulnerability Link", "")
        data_account_id = row.get("Account ID", "")
        data_discovered = row.get("Discovered", "")
        data_unique_id = row.get("Custom Id", "")
        data_ami_id = row.get("Ami Id", "")
        data_labels = row.get("Labels", "")

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
            description=self.get_description(
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
                data_risk_factors,
                data_hostname,
                data_distro,
                data_compliance_id,
                data_result,
                data_packages,
                data_source_package,
                data_published,
                data_services,
                data_vulnerability_link,
                data_account_id,
                data_discovered,
                data_unique_id,
                data_ami_id,
                data_labels,
            ),
            mitigation=data_fix_status,
            references=row.get("Vulnerability Link", ""),
            component_name=textwrap.shorten(
                data_package_name,
                width=200,
                placeholder="...",
            ),
            component_version=data_package_version,
            severity_justification=f"(CVSS v3 base score: {data_cvss})",
            cvssv3_score=float(data_cvss) if data_cvss else None,
            impact=impact_text,
            vuln_id_from_tool=data_vulnerability_id,
            unique_id_from_tool=data_unique_id,
            publish_date=(
                dateutil.parser.parse(row.get("Published"))
                if row.get("Published", None)
                else None
            ),
        )
        finding.unsaved_tags = self.get_tags(row)
        finding.description = finding.description.strip()
        if data_vulnerability_id:
            finding.unsaved_vulnerability_ids = [data_vulnerability_id]

        return finding

    def get_tags(self, row):
        tags = row.get("Custom Tag", None)
        if (tags is not None) and "," in str(tags):
            return str(tags).split(",")
        elif tags is not None:
            return [tags]
        else:
            return [settings.DD_CUSTOM_TAG_PARSER.get("twistlock")]

    def get_description(
        self,
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
        data_risk_factors,
        data_hostname,
        data_distro,
        data_compliance_id,
        data_result,
        data_packages,
        data_source_package,
        data_published,
        data_services,
        data_vulnerability_link,
        data_account_id,
        data_discovered,
        data_unique_id,
        data_ami_id,
        data_labels,
    ):
        description = (
            "<p><strong>Description:</strong> "
            + data_description
            + "</p><p><strong>Type:</strong> "
            + str(data_type)
            + "</p><p><strong>Tag:</strong> "
            + str(data_tag)
            + "</p><p><strong>Cluster:</strong> "
            + str(data_cluster)
            + "</p><p><strong>Namespaces:</strong> "
            + str(data_namespaces)
            + "</p><p><strong>Vulnerable Package:</strong> "
            + str(data_package_name)
            + "</p><p><strong>Vulnerable Package License:</strong> "
            + str(data_package_license)
            + "</p><p><strong>Current Version:</strong> "
            + str(data_package_version)
            + "</p><p><strong>Package path:</strong> "
            + str(data_package_path)
            + "</p>"
            + "</p><p><strong>Name:</strong> "
            + str(data_name)
            + "</p>"
            + "</p><p><strong>Cloud Id:</strong> "
            + str(data_cloud_id)
            + "</p>"
            + "</p><p><strong>Runtime:</strong> "
            + str(data_runtime)
            + "</p>"
            + "</p><p><strong>Risk Factors:</strong> "
            + str(data_risk_factors)
            + "</p>"
            + "</p><p><strong>Cause:</strong> "
            + str(data_cause)
            + "</p>"
            + "</p><p><strong>Found In:</strong> "
            + str(data_found_in)
            + "</p>"
            + "</p><p><strong>PURL:</strong> "
            + str(data_purl)
            + "</p>"
            + "</p><p><strong>Hostname:</strong> "
            + str(data_hostname)
            + "</p>"
            + "</p><p><strong>Distro:</strong> "
            + str(data_distro)
            + "</p>"
            + "</p><p><strong>Compliance ID:</strong> "
            + str(data_compliance_id)
            + "</p>"
            + "</p><p><strong>Result:</strong> "
            + str(data_result)
            + "</p>"
            + "</p><p><strong>Data Packages:</strong> "
            + str(data_packages)
            + "</p>"
            + "</p><p><strong>Data Source Package:</strong> "
            + str(data_source_package)
            + "</p>"
            + "</p><p><strong>Published:</strong> "
            + str(data_published)
            + "</p>"
            + "</p><p><strong>Services:</strong> "
            + str(data_services)
            + "</p>"
            + "</p><p><strong>Vulnerability Link:</strong> "
            + str(data_vulnerability_link)
            + "</p>"
            + "</p><p><strong>Account ID:</strong> "
            + str(data_account_id)
            + "</p>"
            + "</p><p><strong>Discovered:</strong> "
            + str(data_discovered)
            + "</p>"
            + "</p><p><strong>Ami Id:</strong> "
            + str(data_ami_id)
            + "</p>"
            + "</p><p><strong>Custom Id:</strong> "
            + (
                base64.b64decode(data_unique_id).decode("utf-8")
                if data_unique_id
                else "NA"
            )
            + "</p>"
        )

        labels_list = [
            label.strip() for label in str(data_labels).split(",") if label.strip()
        ]
        if labels_list:
            description += "<p><strong>Labels:</strong><ul>"
            for label in labels_list:
                description += f"<li>{label.replace('\"', '')}</li>"
            description += "</ul></p>"
        else:
            description += "<p><strong>Labels:</strong> </p>"

        return description

    def procces_executor(self, row, test):
        finding = self.parse_issue(row, test)
        if finding is not None:
            key = hashlib.md5(
                (
                    finding.severity + "|" + finding.title + "|" + finding.description
                ).encode("utf-8"),
            ).hexdigest()
        return key, finding

    def validate_content(self, content):
        try:
            if not content or not isinstance(content, str):
                return None
            lines = content.splitlines()
            if not lines:
                return None
            return lines[0]
        except IndexError:
            return None

    def parse(self, filename, test):
        if filename is None:
            return None
        content = filename.read()
        dupes = {}
        if isinstance(content, bytes):
            content = content.decode("utf-8")

        first_line = self.validate_content(content)
        if first_line is None:
            first_line = ""
        delimiter = ";" if ";" in first_line else ","
        reader = csv.DictReader(
            io.StringIO(content),
            delimiter=delimiter,
            quotechar='"',
        )
        with ThreadPoolExecutor(max_workers=25) as executor:
            futures = []
            for row in reader:
                futures.append(executor.submit(self.procces_executor, row, test))
            for future in futures:
                key, finding = future.result()
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

            vulnerabilityTree = tree["results"][0].get("vulnerabilities", [])
            packageTree = tree["results"][0].get("packages", [])

            for node in vulnerabilityTree:
                item = get_item(node, test, packageTree, image_metadata)
                unique_key = node["id"] + str(
                    node["packageName"]
                    + str(node["packageVersion"])
                    + str(node["severity"]),
                )
                items[unique_key] = item

            # Parse compliance findings
            if settings.ENABLE_COMPLIANCE_FINDINGS_TWISTLOCK:
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


def get_item(vulnerability, test, packageTree, image_metadata):
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
    
    for package in packageTree:
        if (
            package["name"] == vulnerability["packageName"]
            and package["version"] == vulnerability["packageVersion"]
        ):
            vulnerability["type"] = package["type"]
            break

    description = (
        vulnerability.get("description", "")
        + "<p> Vulnerable Package: "
        + vulnerability["packageName"]
        + "</p><p> Current Version: "
        + str(vulnerability["packageVersion"])
        + "</p><p> Layer Instruction: "
        + vulnerability.get("layerInstruction", "")
        + "</p><p> Package Path: "
        + vulnerability.get("packagePath", "")
        + "</p><p> Type: "
        + vulnerability.get("type", "")
    )

    if vulnerability.get("baseImage"):
        description += "<p> Image Base: " + vulnerability["baseImage"] + "</p>"

    # create the finding object
    finding = Finding(
        title=vulnerability.get("id", "Unknown Vulnerability")
        + ": "
        + vulnerability.get("packageName", "Unknown Package")
        + " - "
        + str(vulnerability.get("packageVersion", "")),
        test=test,
        severity=severity,
        description=description,
        mitigation=status.title(),
        references=vulnerability.get("link"),
        component_name=vulnerability["packageName"],
        component_version=vulnerability["packageVersion"],
        severity_justification=f"Vector: {cvssv3} (CVSS v3 base score: {cvssv3_score})\n\n{riskFactors}",
        cvssv3=cvssv3,
        cvssv3_score=cvssv3_score,
        impact=impact_text,
        vuln_id_from_tool=vulnerability["id"],
        publish_date=(
            dateutil.parser.parse(vulnerability.get("publishedDate"))
            if vulnerability.get("publishedDate", None)
            else None
        ),
    )
    finding.unsaved_tags = [
        (
            vulnerability["customTag"]
            if vulnerability.get("customTag", None)
            else settings.DD_CUSTOM_TAG_PARSER.get("twistlock")
        )
    ]
    finding.unsaved_vulnerability_ids = [vulnerability["id"]]
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
    if severity.lower() in [
        "unimportant",
        "unassigned",
        "negligible",
        "not yet assigned",
    ]:
        return "Low"
    if severity.lower() in ["information", "informational", ""]:
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
