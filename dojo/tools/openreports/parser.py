"""Parser for OpenReports (https://github.com/openreports/reports-api) vulnerability scan reports"""

import json
import logging

from dojo.models import Finding
from dojo.tools.parser_test import ParserTest

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
**Primary URL:** {primary_url}
"""


class OpenreportsParser:
    def get_scan_types(self):
        return ["OpenReports"]

    def get_label_for_scan_types(self, scan_type):
        return "OpenReports"

    def get_description_for_scan_types(self, scan_type):
        return "Import OpenReports JSON report."

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

    def get_tests(self, scan_type, handle):
        try:
            data = json.load(handle)
        except Exception:
            handle.seek(0)
            scan_data = handle.read()
            try:
                data = json.loads(str(scan_data, "utf-8"))
            except Exception:
                data = json.loads(scan_data)

        if data is None:
            return []

        # Handle both single report and list of reports
        reports = []
        if isinstance(data, dict):
            if data.get("kind") == "List" and "items" in data:
                reports = data["items"]
            elif data.get("kind") == "Report":
                reports = [data]
        elif isinstance(data, list):
            reports = data

        # Find all unique sources across all reports
        sources_found = set()
        for report in reports:
            if not isinstance(report, dict) or report.get("kind") != "Report":
                continue
            for result in report.get("results", []):
                source = result.get("source", "OpenReports")
                sources_found.add(source)

        # Create a ParserTest for each source
        tests = []
        for source in sorted(sources_found):
            test = ParserTest(
                name=source,
                parser_type=source,
                version=None,
            )
            test.findings = []

            # Parse all reports and filter findings by source
            for report in reports:
                if not isinstance(report, dict) or report.get("kind") != "Report":
                    continue

                findings = self._parse_report_for_source(test, report, source)
                test.findings.extend(findings)

            tests.append(test)

        return tests

    def _parse_report(self, test, report):
        findings = []

        # Extract metadata
        metadata = report.get("metadata", {})
        report_name = metadata.get("name", "")
        namespace = metadata.get("namespace", "")
        report_uid = metadata.get("uid", "")

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

            finding = self._create_finding_from_result(test, result, service_name, report_name, report_uid)
            if finding:
                findings.append(finding)

        return findings

    def _parse_report_for_source(self, test, report, source_filter):
        findings = []

        # Extract metadata
        metadata = report.get("metadata", {})
        report_name = metadata.get("name", "")
        namespace = metadata.get("namespace", "")
        report_uid = metadata.get("uid", "")

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

            # Filter by source
            result_source = result.get("source", "OpenReports")
            if result_source != source_filter:
                continue

            finding = self._create_finding_from_result(None, result, service_name, report_name, report_uid)
            if finding:
                findings.append(finding)

        return findings

    def _create_finding_from_result(self, test, result, service_name, report_name, report_uid):
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
            title = f"{policy} in {pkg_name}" if policy.startswith("CVE-") else f"{policy}: {message}"

            # Create description
            description = DESCRIPTION_TEMPLATE.format(
                message=message,
                category=category,
                policy=policy,
                result=result_status,
                source=source,
                pkg_name=pkg_name,
                installed_version=installed_version,
                primary_url=primary_url,
            )

            # Determine if fix is available
            fix_available = bool(fixed_version and fixed_version.strip())

            # Set mitigation based on fixed version
            mitigation = f"Upgrade to version: {fixed_version}" if fixed_version else ""

            # Set references
            references = primary_url or ""

            # Determine active status based on result
            active = result_status not in {"skip", "pass"}
            verified = result_status in {"fail", "warn"}

            # Create finding
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
                fix_version=fixed_version or None,
            )

            # Create tags
            tags = [category, source]
            scope_kind = service_name.split("/")[1] if "/" in service_name else ""
            if scope_kind:
                tags.append(scope_kind)

            # Set unsaved_tags attribute
            finding.unsaved_tags = tags

            # Add vulnerability ID if it's a CVE
            if policy.startswith("CVE-"):
                finding.unsaved_vulnerability_ids = [policy]

            # Set vuln_id_from_tool to policy field for display
            finding.vuln_id_from_tool = policy

            return finding  # noqa: TRY300 - This is intentional

        except KeyError as exc:
            logger.warning("Failed to parse OpenReports result due to missing key: %r", exc)
            return None
        except Exception as exc:
            logger.warning("Failed to parse OpenReports result: %r", exc)
            return None
