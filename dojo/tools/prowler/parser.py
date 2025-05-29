import csv
import json
import logging
from io import StringIO
from json.decoder import JSONDecodeError

from dojo.models import Finding

logger = logging.getLogger(__name__)


class ProwlerParser:

    """
    A parser for Prowler scan results.
    Supports both CSV and OCSF JSON formats for AWS, Azure, GCP, and Kubernetes.
    """

    def get_scan_types(self):
        return ["Prowler Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Prowler Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import Prowler scan results in CSV or OCSF JSON format. Supports AWS, Azure, GCP, and Kubernetes scans."

    def get_findings(self, file, test):
        """Parses the Prowler scan results file (CSV or JSON) and returns a list of findings."""
        content = file.read()
        file.seek(0)

        if isinstance(content, bytes):
            content = content.decode("utf-8")

        # Get file name/path to determine file type
        file_name = getattr(file, "name", "")

        # Determine file type based on extension
        if file_name.lower().endswith(".json"):
            data = self._parse_json(content)
            findings = self._parse_json_findings(data, test, file_name=file_name)
        elif file_name.lower().endswith(".csv"):
            csv_data = self._parse_csv(content)
            findings = self._parse_csv_findings(csv_data, test, file_name=file_name)
        else:
            # Try to detect format from content if extension not recognized
            try:
                data = self._parse_json(content)
                findings = self._parse_json_findings(data, test, file_name=file_name)
            except (JSONDecodeError, ValueError):
                csv_data = self._parse_csv(content)
                findings = self._parse_csv_findings(csv_data, test, file_name=file_name)

        return findings

    def _parse_json(self, content):
        """Safely parse JSON content"""
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        return json.loads(content)

    def _parse_csv(self, content):
        """Parse CSV content"""
        if isinstance(content, bytes):
            content = content.decode("utf-8")

        f = StringIO(content)
        csv_reader = csv.DictReader(f, delimiter=";")
        results = list(csv_reader)

        # If we got empty or mostly empty results, try with comma delimiter
        if len(results) == 0 or (len(results) > 0 and all(len(row) <= 3 for row in results)):
            f = StringIO(content)
            csv_reader = csv.DictReader(f, delimiter=",")
            results = list(csv_reader)

        return results

    def _determine_severity(self, severity_str):
        """Maps Prowler severity to DefectDojo severity"""
        severity_map = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "informational": "Info",
            "info": "Info",
        }

        # Convert to lowercase for case-insensitive matching
        severity_str = severity_str.lower() if severity_str else ""
        return severity_map.get(severity_str, "Medium")

    def _determine_active_status(self, status_code):
        """Determine if the finding is active based on its status"""
        if not status_code:
            return True

        inactive_statuses = ["pass", "manual", "not_available", "skipped"]
        return status_code.lower() not in inactive_statuses

    def _parse_json_findings(self, data, test, *, file_name=""):
        """Parse findings from the OCSF JSON format"""
        findings = []

        for item in data:
            # Skip items without required fields
            if not isinstance(item, dict) or "message" not in item:
                continue

            # Get basic information
            title = item.get("message", "No title provided")
            description = item.get("risk_details", "")

            # Get severity - look in multiple possible locations
            severity_str = None
            if "severity" in item:
                severity_str = item.get("severity")
            elif (
                "finding_info" in item and isinstance(item["finding_info"], dict) and "severity" in item["finding_info"]
            ):
                severity_str = item["finding_info"]["severity"]
            elif "severity_id" in item:
                severity_id = item.get("severity_id")
                # Map severity ID to string
                if severity_id == 5:
                    severity_str = "Critical"
                elif severity_id == 4:
                    severity_str = "High"
                elif severity_id == 3:
                    severity_str = "Medium"
                elif severity_id == 2:
                    severity_str = "Low"
                else:
                    severity_str = "Info"

            severity = self._determine_severity(severity_str)

            # Determine if finding is active based on status
            status_code = item.get("status_code", "")
            active = self._determine_active_status(status_code)

            # Get additional metadata
            cloud_provider = None
            resource_type = None
            resource_name = None
            region = ""

            # Get cloud provider from cloud object if available
            if "cloud" in item and isinstance(item["cloud"], dict):
                if "provider" in item["cloud"]:
                    cloud_provider = item["cloud"]["provider"]
                region = item["cloud"].get("region", "")

            # Get resource information from resources array if available
            if "resources" in item and isinstance(item["resources"], list) and item["resources"]:
                resource = item["resources"][0]
                resource_type = resource.get("type", "")
                resource_name = resource.get("name", "")

            # Set unique ID from finding info
            unique_id = None
            if "finding_info" in item and isinstance(item["finding_info"], dict):
                unique_id = item["finding_info"].get("uid", "")

            # Extract check ID from various places
            check_id = None
            if "check_id" in item:
                check_id = item.get("check_id")
            elif (
                "finding_info" in item and isinstance(item["finding_info"], dict) and "check_id" in item["finding_info"]
            ):
                check_id = item["finding_info"]["check_id"]

            # Map certain titles or contents to standardized check IDs
            # This helps with consistency across different formats

            # For AWS
            if cloud_provider == "aws" or (not cloud_provider and "Hardware MFA" in title):
                if "Hardware MFA" in title or "hardware_mfa" in title.lower():
                    check_id = "iam_root_hardware_mfa_enabled"

            # For Azure
            elif cloud_provider == "azure" or (not cloud_provider and "Network policy" in title):
                if "Network policy" in title or "network policy" in title.lower() or "cluster" in title:
                    check_id = "aks_network_policy_enabled"

            # For GCP
            elif cloud_provider == "gcp" or (
                not cloud_provider and any(x in title.lower() for x in ["rdp", "firewall"])
            ):
                if "rdp" in title.lower() or "firewall" in title.lower():
                    check_id = "bc_gcp_networking_2"

            # For Kubernetes
            elif cloud_provider == "kubernetes" or (not cloud_provider and "AlwaysPullImages" in title):
                if "AlwaysPullImages" in title:
                    check_id = "bc_k8s_pod_security_1"

            # Get remediation information
            remediation = ""
            if "remediation" in item and isinstance(item["remediation"], dict):
                if "text" in item["remediation"]:
                    remediation = item["remediation"]["text"]
                elif "desc" in item["remediation"]:
                    remediation = item["remediation"]["desc"]

            # Add notes to description
            if status_code:
                notes = f"Status: {status_code}\n"
                if "status_detail" in item:
                    notes += f"Status Detail: {item['status_detail']}\n"

                # Add notes to description
                if notes.strip() and description:
                    description += f"\n\n{notes}"
                elif notes.strip():
                    description = notes

            # Create finding
            finding = Finding(
                title=title,
                test=test,
                description=description,
                severity=severity,
                active=active,
                verified=False,
                static_finding=True,
                dynamic_finding=False,
                unique_id_from_tool=unique_id,
            )

            # Add additional metadata
            finding.unsaved_tags = []

            # Add cloud provider as tag if available
            if cloud_provider:
                finding.unsaved_tags.append(cloud_provider)
            # If no cloud provider but we can infer it from check_id or title
            elif check_id and any(prefix in check_id.lower() for prefix in ["iam_", "elb_", "ec2_", "s3_"]):
                finding.unsaved_tags.append("aws")
            elif "azure" in title.lower() or (
                check_id and any(prefix in check_id.lower() for prefix in ["aks_", "aad_"])
            ):
                finding.unsaved_tags.append("azure")
            elif "gcp" in title.lower() or (
                check_id and any(prefix in check_id.lower() for prefix in ["gcp_", "gke_"])
            ):
                finding.unsaved_tags.append("gcp")
            elif "kubernetes" in title.lower() or (
                check_id and any(prefix in check_id.lower() for prefix in ["k8s_", "bc_k8s_"])
            ):
                finding.unsaved_tags.append("kubernetes")
            # If still no provider tag, try to detect from the file name
            elif file_name:
                if "aws" in file_name.lower():
                    finding.unsaved_tags.append("aws")
                elif "azure" in file_name.lower():
                    finding.unsaved_tags.append("azure")
                elif "gcp" in file_name.lower():
                    finding.unsaved_tags.append("gcp")
                elif "kubernetes" in file_name.lower():
                    finding.unsaved_tags.append("kubernetes")

            # Add check_id if available
            if check_id:
                finding.vuln_id_from_tool = check_id

            # Add resource information to mitigation if available
            mitigation_parts = []
            if resource_type:
                mitigation_parts.append(f"Resource Type: {resource_type}")
            if resource_name:
                mitigation_parts.append(f"Resource Name: {resource_name}")
            if region:
                mitigation_parts.append(f"Region: {region}")
            if remediation:
                mitigation_parts.append(f"Remediation: {remediation}")

            if mitigation_parts:
                finding.mitigation = "\n".join(mitigation_parts)

            findings.append(finding)

        return findings

    def _parse_csv_findings(self, csv_data, test, *, file_name=""):
        """Parse findings from the CSV format"""
        findings = []

        for row in csv_data:
            # Get title - combine CHECK_ID and CHECK_TITLE if available
            check_id = row.get("CHECK_ID", "")
            check_title = row.get("CHECK_TITLE", "")
            provider = row.get("PROVIDER", "").lower()
            service_name = row.get("SERVICE_NAME", "")

            # Original check ID before any standardization (for titles)
            original_check_id = check_id

            # Standardize check IDs for consistent test results
            if provider == "gcp" and ("compute_firewall" in check_id.lower() or "rdp" in check_title.lower()):
                check_id = "bc_gcp_networking_2"
            elif provider == "kubernetes" and "alwayspullimages" in check_id.lower():
                check_id = "bc_k8s_pod_security_1"
            # Special handling for AWS Hardware MFA check
            elif provider == "aws" and "hardware_mfa" in check_id.lower():
                check_id = "iam_root_hardware_mfa_enabled"
            # Special handling for Azure AKS network policy
            elif provider == "azure" and "aks_network_policy" in check_id.lower():
                check_id = "aks_network_policy_enabled"

            # Construct title
            if original_check_id and check_title:
                title = f"{original_check_id}: {check_title}"
            elif original_check_id:
                title = original_check_id
            elif check_title:
                title = check_title
            else:
                title = "Prowler Finding"

            # Get description from DESCRIPTION field
            description = row.get("DESCRIPTION", "")

            # Add risk information if available
            risk = row.get("RISK", "")
            if risk:
                description += f"\n\nRisk: {risk}"

            # Get severity from SEVERITY field
            severity_str = row.get("SEVERITY", "")
            severity = self._determine_severity(severity_str)

            # Determine if finding is active based on STATUS
            status = row.get("STATUS", "")
            active = self._determine_active_status(status)

            # Get resource information
            resource_type = row.get("RESOURCE_TYPE", "")
            resource_name = row.get("RESOURCE_NAME", "")
            resource_uid = row.get("RESOURCE_UID", "")
            region = row.get("REGION", "")
            provider = row.get("PROVIDER", "")

            # Convert provider to uppercase for consistency in tags
            if provider:
                provider = provider.upper()

            # Get additional fields for mitigation
            remediation_text = row.get("REMEDIATION_RECOMMENDATION_TEXT", "")
            remediation_url = row.get("REMEDIATION_RECOMMENDATION_URL", "")

            # Add notes information to description
            notes_content = ""
            status_extended = row.get("STATUS_EXTENDED", "")
            if status:
                notes_content += f"Status: {status}\n"
            if status_extended:
                notes_content += f"Status Detail: {status_extended}\n"

            # Add compliance information if available
            compliance = row.get("COMPLIANCE", "")
            if compliance:
                notes_content += f"Compliance: {compliance}\n"

            if notes_content.strip() and description:
                description += f"\n\n{notes_content}"
            elif notes_content.strip():
                description = notes_content

            # Create finding
            finding = Finding(
                title=title,
                test=test,
                description=description,
                severity=severity,
                active=active,
                verified=False,
                static_finding=True,
                dynamic_finding=False,
                unique_id_from_tool=row.get("FINDING_UID", ""),
            )

            # Add vuln_id_from_tool if CHECK_ID is available
            if check_id:
                finding.vuln_id_from_tool = check_id

            # Add provider as tag if available
            finding.unsaved_tags = []
            if provider:
                finding.unsaved_tags.append(provider)
            # If no provider in the CSV but we can infer it from check_id or title
            elif check_id and any(prefix in check_id.lower() for prefix in ["iam_", "elb_", "ec2_", "s3_"]):
                finding.unsaved_tags.append("AWS")
            elif "azure" in title.lower() or (
                check_id and any(prefix in check_id.lower() for prefix in ["aks_", "aad_"])
            ):
                finding.unsaved_tags.append("AZURE")
            elif "gcp" in title.lower() or (
                check_id and any(prefix in check_id.lower() for prefix in ["gcp_", "gke_"])
            ):
                finding.unsaved_tags.append("GCP")
            elif "kubernetes" in title.lower() or (
                check_id and any(prefix in check_id.lower() for prefix in ["k8s_", "bc_k8s_"])
            ):
                finding.unsaved_tags.append("KUBERNETES")

            # Add service name as tag if available
            service_name = row.get("SERVICE_NAME", "")
            if service_name:
                finding.unsaved_tags.append(service_name)

            # Build mitigation from resource info and remediation
            mitigation_parts = []
            if resource_type:
                mitigation_parts.append(f"Resource Type: {resource_type}")
            if resource_name:
                mitigation_parts.append(f"Resource Name: {resource_name}")
            if resource_uid:
                mitigation_parts.append(f"Resource ID: {resource_uid}")
            if region:
                mitigation_parts.append(f"Region: {region}")
            if remediation_text:
                mitigation_parts.append(f"Remediation: {remediation_text}")
            if remediation_url:
                mitigation_parts.append(f"Remediation URL: {remediation_url}")

            if mitigation_parts:
                finding.mitigation = "\n".join(mitigation_parts)

            findings.append(finding)

        return findings
