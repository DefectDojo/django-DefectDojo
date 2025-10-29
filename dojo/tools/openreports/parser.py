"""Parser for OpenReports (https://github.com/openreports/reports-api) vulnerability scan reports"""

import json
import logging

from dojo.models import Finding

logger = logging.getLogger(__name__)


OPENREPORTS_SEVERITIES = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

DESCRIPTION_TEMPLATE = """{message}

**Category:** {category}
**Policy:** {policy}
**Result:** {result}
**Source:** {source}
**Package Name:** {pkg_name}
**Installed Version:** {installed_version}
**Fixed Version:** {fixed_version}
**Primary URL:** {primary_url}
"""


class OpenreportsParser:
    def get_scan_types(self):
        return ["OpenReports Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "OpenReports Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import OpenReports JSON scan report."

    def get_findings(self, scan_file, test):
        scan_data = scan_file.read()

        try:
            data = json.loads(str(scan_data, "utf-8"))
        except Exception:
            data = json.loads(scan_data)

        if data is None:
            return []

        findings = []

        # Handle both single report and list of reports
        reports = []
        if isinstance(data, dict):
            # Check if it's a Kubernetes List object
            if data.get("kind") == "List" and "items" in data:
                reports = data["items"]
            # Check if it's a single Report object
            elif data.get("kind") == "Report":
                reports = [data]
        elif isinstance(data, list):
            reports = data

        for report in reports:
            if not isinstance(report, dict) or report.get("kind") != "Report":
                continue

            findings.extend(self._parse_report(test, report))

        return findings

    def _parse_report(self, test, report):
        findings = []
        
        # Extract metadata
        metadata = report.get("metadata", {})
        report_name = metadata.get("name", "")
        namespace = metadata.get("namespace", "")
        
        # Extract scope information
        scope = report.get("scope", {})
        scope_kind = scope.get("kind", "")
        scope_name = scope.get("name", "")
        
        # Create service identifier from scope and metadata
        service_name = f"{namespace}/{scope_kind}/{scope_name}" if namespace else f"{scope_kind}/{scope_name}"
        
        # Extract results
        results = report.get("results", [])
        
        for result in results:
            if not isinstance(result, dict):
                continue

            finding = self._create_finding_from_result(test, result, service_name, report_name)
            if finding:
                findings.append(finding)

        return findings

    def _create_finding_from_result(self, test, result, service_name, report_name):
        try:
            # Extract basic fields
            message = result.get("message", "")
            category = result.get("category", "")
            policy = result.get("policy", "")
            result_status = result.get("result", "")
            severity = result.get("severity", "info").lower()
            source = result.get("source", "")
            
            # Extract properties
            properties = result.get("properties", {})
            pkg_name = properties.get("pkgName", "")
            installed_version = properties.get("installedVersion", "")
            fixed_version = properties.get("fixedVersion", "")
            primary_url = properties.get("primaryURL", "")
            
            # Convert severity to DefectDojo format
            severity_normalized = OPENREPORTS_SEVERITIES.get(severity, "Info")
            
            # Create title
            if policy.startswith("CVE-"):
                title = f"{policy} in {pkg_name}"
            else:
                title = f"{policy}: {message}"
            
            # Create description
            description = DESCRIPTION_TEMPLATE.format(
                message=message,
                category=category,
                policy=policy,
                result=result_status,
                source=source,
                pkg_name=pkg_name,
                installed_version=installed_version,
                fixed_version=fixed_version,
                primary_url=primary_url,
            )
            
            # Determine if fix is available
            fix_available = bool(fixed_version and fixed_version.strip())
            
            # Set mitigation based on fixed version
            mitigation = f"Upgrade to version: {fixed_version}" if fixed_version else ""
            
            # Set references
            references = primary_url if primary_url else ""
            
            # Determine active status based on result
            active = result_status not in ["skip", "pass"]
            verified = result_status in ["fail", "warn"]
            
            # Create tags
            tags = [category, source]
            if scope_kind := service_name.split("/")[1] if "/" in service_name else "":
                tags.append(scope_kind)
            
            finding = Finding(
                test=test,
                title=title,
                description=description,
                severity=severity_normalized,
                references=references,
                mitigation=mitigation,
                component_name=pkg_name,
                component_version=installed_version,
                service=service_name,
                active=active,
                verified=verified,
                static_finding=True,
                dynamic_finding=False,
                fix_available=fix_available,
                tags=tags,
            )
            
            # Add vulnerability ID if it's a CVE
            if policy.startswith("CVE-"):
                finding.unsaved_vulnerability_ids = [policy]
            
            return finding
            
        except KeyError as exc:
            logger.warning("Failed to parse OpenReports result due to missing key: %r", exc)
            return None
        except Exception as exc:
            logger.warning("Failed to parse OpenReports result: %r", exc)
            return None
