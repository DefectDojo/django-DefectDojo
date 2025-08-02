import json
from contextlib import suppress
from datetime import datetime

from dojo.models import Finding


class SnykIssueApiParser:
    def get_scan_types(self):
        return ["Snyk Issue API Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Snyk Issue API output file can be imported in JSON format."

    def get_findings(self, json_output, test):
        tree = self.parse_json(json_output)
        return self.process_tree(tree, test)

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

    def process_tree(self, tree, test):
        if not tree or "data" not in tree:
            return []

        findings = []
        for issue in tree.get("data", []):
            finding = self.get_finding(issue, test)
            if finding:
                findings.append(finding)
        return findings

    def get_finding(self, issue, test):
        # Check top-level type must be "issue" as "packages" have their own API it seems.
        if not issue or issue.get("type") != "issue":
            return None

        attributes = issue.get("attributes", {})

        # Check attributes-level type must be "code"
        # Other items are not supported yet due to a lack of samples and lack of documentation
        # package_vulnerability,license,cloud,code,customconfig
        if attributes.get("type") != "code":
            return None

        # Extract CWE classes
        cwes = []
        for class_info in attributes.get("classes", []):
            if class_info.get("source") == "CWE":
                cwe_id = class_info.get("id", "").replace("CWE-", "")
                if cwe_id.isdigit():
                    cwes.append(int(cwe_id))

        # Extract location information, fixability and collect all source locations for impact
        file_path = None
        line = None
        fix_available = False
        impact_locations = []

        for coordinate in attributes.get("coordinates", []):
            # Check if any fix is available
            if coordinate.get("is_fixable_snyk") or \
               coordinate.get("is_fixable_upstream") or \
               coordinate.get("is_fixable_manually"):
                fix_available = True

            for representation in coordinate.get("representations", []):
                if "sourceLocation" in representation:
                    location = representation["sourceLocation"]
                    region = location.get("region", {})
                    start = region.get("start", {})
                    end = region.get("end", {})

                    # Store location details for impact field
                    impact_locations.append([
                        "Source Location:",
                        f"File: {location.get('file', 'Unknown')}",
                        f"Commit: {location.get('commit_id', 'Unknown')}",
                        f"Lines: {start.get('line', '?')}-{end.get('line', '?')}",
                        f"Columns: {start.get('column', '?')}-{end.get('column', '?')}",
                        "",  # Empty line between locations
                    ])

                    # Store first location for finding fields
                    if not file_path:
                        file_path = location.get("file")
                        if region:
                            line = start.get("line")

        # Map severity levels
        severity_map = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
        }
        severity = severity_map.get(attributes.get("effective_severity_level", "").lower(), "Info")

        # Parse created_at date
        created = None
        if attributes.get("created_at"):
            with suppress(ValueError):
                created = datetime.strptime(attributes["created_at"], "%Y-%m-%dT%H:%M:%S.%fZ")
            if not created:
                with suppress(ValueError):
                    created = datetime.strptime(attributes["created_at"], "%Y-%m-%dT%H:%M:%SZ")

        # Create finding
        finding = Finding(
            title=attributes.get("title", ""),
            test=test,
            severity=severity,
            description=attributes.get("description", ""),
            static_finding=True,
            dynamic_finding=False,
            unique_id_from_tool=issue.get("id"),
            file_path=file_path,
            line=line,
            out_of_scope=attributes.get("ignored", False),
            active=attributes.get("status") == "open" and not attributes.get("ignored", False),
            verified=True,
            cwe=cwes[0] if cwes else None,
            date=created,
        )

        # Set fix_available if the field exists in the model
        if hasattr(finding, "fix_available"):
            finding.fix_available = fix_available

        # Add risk score if available
        risk = attributes.get("risk", {})
        if risk and "score" in risk:
            score = risk["score"]
            if isinstance(score, dict):
                finding.severity_justification = (
                    f"Risk Score: {score.get('value', 'N/A')} "
                    f"(Model: {score.get('model', 'N/A')})"
                )

        # Add additional CWEs as references
        if len(cwes) > 1:
            finding.references = "Additional CWEs: " + ", ".join(f"CWE-{cwe}" for cwe in cwes[1:])

        # Add problem details and all source locations to impact
        impact_details = []

        # Add problem information
        problems = attributes.get("problems", [])
        if problems:
            problem = problems[0]  # Take the first problem
            impact_details.extend([
                f"Source: {problem.get('source', 'Unknown')}",
                f"Type: {problem.get('type', 'Unknown')}",
                f"Last Updated: {problem.get('updated_at', 'Unknown')}",
                f"Severity: {severity}",
                "",  # Empty line before locations
            ])

        # Add all source locations
        for location in impact_locations:
            impact_details.extend(location)

        if impact_details:
            finding.impact = "\n".join(impact_details).rstrip()

        return finding
