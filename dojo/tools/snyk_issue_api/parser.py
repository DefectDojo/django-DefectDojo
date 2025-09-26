import json
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

    def extract_cwe_classes(self, attributes):
        cwes = []
        for class_info in attributes.get("classes", []):
            if class_info.get("source") == "CWE":
                cwe_id = class_info.get("id", "").replace("CWE-", "")
                if cwe_id.isdigit():
                    cwes.append(int(cwe_id))

        return cwes

    def extract_if_fix_is_available(self, finding_type, coordinates):
        if coordinates is None:
            return False

        for coordinate in coordinates:
            # Check if any fix is available
            if finding_type == "code":
                if coordinate.get("is_fixable_snyk") or \
                    coordinate.get("is_fixable_upstream") or \
                    coordinate.get("is_fixable_manually"):
                    return True

            if finding_type == "package_vulnerability":
                if coordinate.get("is_fixable_snyk") or \
                    coordinate.get("is_fixable_upstream") or \
                    coordinate.get("is_fixable_manually") or \
                    coordinate.get("is_patchable") or \
                    coordinate.get("is_pinnable") or \
                    coordinate.get("is_upgradeable"):
                    return True
        return False

    def extract_coordinate_data(self, is_type_code, coordinates):
        file_path = None
        line = None  # Always None for SCA
        component_name = None
        component_version = None
        reachable = False   # SCA only
        impact_locations = []

        for coordinate in coordinates:
            if not is_type_code:
                if coordinate.get("reachability") != "not-applicable":
                    reachable = True

            for representation in coordinate.get("representations", []):
                if not is_type_code:
                    if "dependency" in representation:
                        dependency = representation["dependency"]
                        component_name = dependency.get("package_name")
                        component_version = dependency.get("package_version")
                        file_path = component_name
                elif "sourceLocation" in representation:
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

        return file_path, line, component_name, component_version, reachable, impact_locations

    def get_exploit_details(self, exploit_details):
        if exploit_details:
            sources = exploit_details.get("sources", [])
            if sources:
                return [f"Exploit Sources: {', '.join(sources)}", ""]

        return None

    def extract_problems(self, problems):
        if problems:
            problem = problems[0]  # Take the first problem
            return [
                f"id: {problem.get('id', 'Unknown')}",
                f"Source: {problem.get('source', 'Unknown')}",
                f"Type: {problem.get('type', 'Unknown')}",
                f"URL: {problem.get('url', 'Unknown')}" if problem.get("url") else "",
                f"Last Updated: {problem.get('updated_at', 'Unknown')}",
                "",  # Empty line before locations
            ]
        return None

    def extract_problem_ids(self, problems):
        ids = []
        if problems:
            for problem in problems:
                if "id" in problem:
                    # using .extend here adds character by character to the array
                    ids.append(problem["id"])  # noqa: PERF401
        return ids

    def extract_risk_score(self, risk):
        if risk and "score" in risk:
            score = risk["score"]
            if isinstance(score, dict):
                return (
                    f"Risk Score: {score.get('value', 'N/A')} "
                    f"(Model: {score.get('model', 'N/A')})"
                )
        return None

    def extract_cvss_severities(self, severities, version):
        for severity in severities:
            if version in severity.get("version"):
                # returning first matching severity
                return severity.get("vector"), severity.get("score")

        return None, None

    def extract_convert_created_date(self, created_at):
        if created_at:
            created_str = created_at
            # Parse the date string and convert to yyyy-mm-dd format
            try:
                created_date = datetime.fromisoformat(created_str)
                return created_date.strftime("%Y-%m-%d")
            except (ValueError, AttributeError):
                return None

        return None

    def get_finding(self, issue, test):
        # Check top-level type must be "issue" as "packages" have their own API it seems.
        if not issue or issue.get("type") != "issue":
            return None

        attributes = issue.get("attributes", {})

        # Check attributes-level type - support both code and package_vulnerability
        issue_type = attributes.get("type")

        if issue_type not in {"code", "package_vulnerability"}:
            return None

        cwes = self.extract_cwe_classes(attributes)

        impact_details = []

        problem = self.extract_problems(attributes.get("problems", []))
        if problem:
            impact_details.extend(problem)

        # Add exploit details if available, SCA only
        exploit_details = self.get_exploit_details(attributes.get("exploit_details", {}))
        if exploit_details:
            impact_details.extend(exploit_details)

        # Map severity levels
        severity_map = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
        }

        severity = severity_map.get(attributes.get("effective_severity_level", "").lower(), "Info")

        created = self.extract_convert_created_date(attributes.get("created_at"))

        is_out_of_scope = False  # attributes.get("is_out_of_scope", False)

        file_path, line, component_name, component_version, reachable, impact_locations = self.extract_coordinate_data(issue_type == "code", attributes.get("coordinates", []))

        # Locations (Code only)
        if impact_locations:
            for location in impact_locations:
                impact_details.extend(location)

        # Add package details (SCA only)
        if component_name:
            impact_details.extend([
                "Package Details:",
                f"Package: {component_name}",
                f"Version: {component_version or 'Unknown'}",
                "",
            ])

        impact_details.append(f"Reachable: {'Yes' if reachable else 'No'}")

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
            out_of_scope=is_out_of_scope,
            active=attributes.get("status") == "open" and not attributes.get("ignored", False),
            # not all open issues are verified, only fixed and ignored
            verified=attributes.get("ignored", True) or attributes.get("status") == "resolved",
            false_p=attributes.get("ignored"),
            # mitigated is type "date", not "boolean"
            is_mitigated=attributes.get("status") == "resolved",
            cwe=cwes[0] if cwes else None,
            date=created,
            component_name=component_name,
            component_version=component_version,
            risk_accepted=False,
        )

        # sca only
        if attributes.get("key"):
            finding.vuln_id_from_tool = attributes.get("key")

        if attributes.get("severities"):
            v3vector, v3score = self.extract_cvss_severities(attributes.get("severities", {}), "3")
            v4vector, v4score = self.extract_cvss_severities(attributes.get("severities", {}), "4")

            if v3vector and v3score:
                finding.cvssv3 = v3vector
                finding.cvssv3_score = v3score

            if v4vector and v4score:
                finding.cvssv4 = v4vector
                finding.cvssv4_score = v4score

        finding.unsaved_vulnerability_ids = self.extract_problem_ids(attributes.get("problems", []))

        finding.fix_available = self.extract_if_fix_is_available(issue_type, attributes.get("coordinates", []))

        # Add risk score if available
        risk = self.extract_risk_score(attributes.get("risk", {}))

        if risk:
            finding.severity_justification = risk

        # Add additional CWEs as references
        if len(cwes) > 1:
            finding.references = "Additional CWEs: " + ", ".join(f"CWE-{cwe}" for cwe in cwes[1:])

        # Set impact with details
        if impact_details:
            finding.impact = "\n".join(impact_details).rstrip()

        return finding
