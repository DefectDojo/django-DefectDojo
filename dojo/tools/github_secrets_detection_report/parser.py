import json

from dojo.models import Finding


class GithubSecretsDetectionReportParser:
    def get_scan_types(self):
        return ["Github Secrets Detection Report Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Github Secrets Detection Report Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Github Secrets Detection Report report file can be imported in JSON format (option --json)."

    def get_findings(self, file, test):
        data = json.load(file)

        if not isinstance(data, list):
            error_msg = "Invalid GitHub secrets detection report format, expected a JSON list of alerts."
            raise TypeError(error_msg)

        findings = []
        for alert in data:
            # Extract basic alert information
            alert_number = alert.get("number")
            state = alert.get("state", "open")
            secret_type = alert.get("secret_type", "Unknown")
            secret_type_display_name = alert.get("secret_type_display_name", secret_type)
            html_url = alert.get("html_url", "")

            # Create title
            title = f"Exposed Secret Detected: {secret_type_display_name}"

            # Build description
            desc_lines = []
            if html_url:
                desc_lines.append(f"**GitHub Alert**: [{html_url}]({html_url})")

            desc_lines.extend([f"**Secret Type**: {secret_type_display_name}", f"**Alert State**: {state}"])

            # Add repository information
            repository = alert.get("repository", {})
            if repository:
                repo_full_name = repository.get("full_name")
                if repo_full_name:
                    desc_lines.append(f"**Repository**: {repo_full_name}")

            # Add location information
            first_location = alert.get("first_location_detected", {})
            if first_location:
                file_path = first_location.get("path")
                start_line = first_location.get("start_line")
                end_line = first_location.get("end_line")

                if file_path:
                    desc_lines.append(f"**File Path**: {file_path}")
                    if start_line:
                        if end_line and end_line != start_line:
                            desc_lines.append(f"**Lines**: {start_line}-{end_line}")
                        else:
                            desc_lines.append(f"**Line**: {start_line}")

            # Add resolution information
            resolution = alert.get("resolution")
            if resolution:
                desc_lines.append(f"**Resolution**: {resolution}")

                resolved_by = alert.get("resolved_by")
                if resolved_by:
                    resolved_by_login = resolved_by.get("login", "Unknown")
                    desc_lines.append(f"**Resolved By**: {resolved_by_login}")

                resolved_at = alert.get("resolved_at")
                if resolved_at:
                    desc_lines.append(f"**Resolved At**: {resolved_at}")

                resolution_comment = alert.get("resolution_comment")
                if resolution_comment:
                    desc_lines.append(f"**Resolution Comment**: {resolution_comment}")

            # Add push protection information
            push_protection_bypassed = alert.get("push_protection_bypassed", False)
            if push_protection_bypassed:
                desc_lines.append("**Push Protection Bypassed**: True")

                bypassed_by = alert.get("push_protection_bypassed_by")
                if bypassed_by:
                    bypassed_by_login = bypassed_by.get("login", "Unknown")
                    desc_lines.append(f"**Bypassed By**: {bypassed_by_login}")

                bypassed_at = alert.get("push_protection_bypassed_at")
                if bypassed_at:
                    desc_lines.append(f"**Bypassed At**: {bypassed_at}")
            else:
                desc_lines.append("**Push Protection Bypassed**: False")

            # Add additional metadata
            validity = alert.get("validity", "unknown")
            desc_lines.append(f"**Validity**: {validity}")

            publicly_leaked = alert.get("publicly_leaked", False)
            desc_lines.append(f"**Publicly Leaked**: {'Yes' if publicly_leaked else 'No'}")

            multi_repo = alert.get("multi_repo", False)
            desc_lines.append(f"**Multi-Repository**: {'Yes' if multi_repo else 'No'}")

            has_more_locations = alert.get("has_more_locations", False)
            if has_more_locations:
                desc_lines.append("**Note**: This secret has been detected in multiple locations")

            description = "\n\n".join(desc_lines)

            # Determine severity based on state and other factors
            if state == "resolved":
                severity = "Info"
            elif validity == "active" and publicly_leaked:
                severity = "Critical"
            elif validity == "active":
                severity = "High"
            else:
                severity = "Medium"

            # Create finding
            finding = Finding(
                title=title,
                test=test,
                description=description,
                severity=severity,
                static_finding=True,
                dynamic_finding=False,
                vuln_id_from_tool=str(alert_number) if alert_number else None,
            )

            # Set file path and line information
            if first_location:
                finding.file_path = first_location.get("path")
                finding.line = first_location.get("start_line")

            # Set external URL
            if html_url:
                finding.url = html_url

            findings.append(finding)

        return findings
