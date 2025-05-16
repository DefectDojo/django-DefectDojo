import hashlib
import logging
import re

from dojo.models import Finding

logger = logging.getLogger(__name__)

# Mapping from Wiz severities to DefectDojo severities
SEVERITY_MAPPING = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFORMATIONAL": "Info",
    "INFO": "Info",
    "UNKNOWN": "Info",  # Default for unknown severities
}


class WizcliParsers:

    @staticmethod
    def get_severity(severity_str):
        """Maps Wiz severity strings to DefectDojo standard TitleCase."""
        if severity_str:
            return SEVERITY_MAPPING.get(severity_str.upper(), "Info")
        return "Info"  # Default if severity is missing or None

    @staticmethod
    def extract_reference_link(text):
        """Extracts potential URL from remediation instructions."""
        if not text:
            return None
        # Basic regex to find URLs, might need refinement
        match = re.search(r"(https?://[^\s)]+)", text)
        return match.group(1) if match else None

    @staticmethod
    def _generate_unique_id(components: list) -> str:
        """
        Generates a stable unique ID for findings.

        Args:
            components: List of components to use for ID generation

        """
        # Filter out None and empty values
        filtered_components = [str(c).strip() for c in components if c is not None and str(c).strip()]

        # Sort components for consistent order regardless of input order
        filtered_components = sorted(filtered_components)

        id_string = "|".join(filtered_components)
        hash_object = hashlib.sha256(id_string.encode("utf-8"))
        return hash_object.hexdigest()

    @staticmethod
    def parse_libraries(libraries_data, test):
        """
        Parses library vulnerability data into granular DefectDojo findings.
        Creates one finding per unique vulnerability (CVE/ID) per library instance (name/version/path).
        """
        findings_list = []
        if not libraries_data:
            return findings_list

        for lib_item in libraries_data:
            lib_name = lib_item.get("name", "N/A")
            lib_version = lib_item.get("version", "N/A")
            lib_path = lib_item.get("path", "N/A")
            lib_line = lib_item.get("startLine")

            vulnerabilities_in_lib_instance = lib_item.get("vulnerabilities", [])
            if not vulnerabilities_in_lib_instance:
                continue

            for vuln_data in vulnerabilities_in_lib_instance:
                vuln_name = vuln_data.get("name", "N/A")
                severity_str = vuln_data.get("severity")
                severity = WizcliParsers.get_severity(severity_str)
                fixed_version = vuln_data.get("fixedVersion")
                source_url = vuln_data.get("source", "N/A")
                vuln_description_from_wiz = vuln_data.get("description")
                score_str = vuln_data.get("score")
                has_exploit = vuln_data.get("hasExploit", False)
                has_cisa_kev_exploit = vuln_data.get("hasCisaKevExploit", False)

                title = f"{lib_name} {lib_version} - {vuln_name}"

                description_parts = [
                    f"**Vulnerability**: `{vuln_name}`",
                    f"**Severity**: {severity}",
                    f"**Library**: `{lib_name}`",
                    f"**Version**: `{lib_version}`",
                    f"**Path/Manifest**: `{lib_path}`",
                ]
                if lib_line is not None:
                    description_parts.append(f"**Line in Manifest**: {lib_line}")

                if fixed_version:
                    description_parts.append(f"**Fixed Version**: {fixed_version}")
                    mitigation = f"Update `{lib_name}` to version `{fixed_version}` or later in path/manifest `{lib_path}`."
                else:
                    description_parts.append("**Fixed Version**: N/A")
                    mitigation = f"No fixed version available from Wiz. Investigate `{vuln_name}` for `{lib_name}` in `{lib_path}` and apply vendor guidance or risk acceptance."

                description_parts.append(f"**Source**: {source_url}")
                if vuln_description_from_wiz:
                    description_parts.append(f"\n**Details from Wiz**:\n{vuln_description_from_wiz}\n")
                if score_str is not None:
                    description_parts.append(f"**CVSS Score (from Wiz)**: {score_str}")
                description_parts.extend([
                    f"**Has Exploit (Known)**: {has_exploit}",
                    f"**In CISA KEV**: {has_cisa_kev_exploit}",
                ])

                failed_policies = vuln_data.get("failedPolicyMatches", [])
                if failed_policies:
                    description_parts.append("\n**Failed Policies**:")
                    for match in failed_policies:
                        policy = match.get("policy", {})
                        description_parts.append(f"- {policy.get('name', 'N/A')} (ID: {policy.get('id', 'N/A')})")
                ignored_policies = vuln_data.get("ignoredPolicyMatches", [])
                if ignored_policies:
                    description_parts.append("\n**Ignored Policies**:")
                    for match in ignored_policies:
                        policy = match.get("policy", {})
                        reason = match.get("ignoreReason", "N/A")
                        description_parts.append(f"- {policy.get('name', 'N/A')} (ID: {policy.get('id', 'N/A')}), Reason: {reason}")

                full_description = "\n".join(description_parts)
                references = source_url if source_url != "N/A" else None

                # Generate unique ID using stable components including file path
                unique_id = WizcliParsers._generate_unique_id(
                    [lib_name, lib_version, vuln_name, lib_path],
                )

                finding = Finding(
                    test=test,
                    title=title,
                    description=full_description,
                    severity=severity,
                    mitigation=mitigation,
                    file_path=lib_path,
                    line=lib_line if lib_line is not None else 0,
                    component_name=lib_name,
                    component_version=lib_version,
                    static_finding=True,
                    dynamic_finding=False,
                    unique_id_from_tool=unique_id,
                    vuln_id_from_tool=vuln_name,
                    references=references,
                    active=True,  # Always set as active since we don't have status from Wiz
                )
                if score_str is not None:
                    try:
                        finding.cvssv3_score = float(score_str)
                    except (ValueError, TypeError):
                        logger.warning(f"Could not convert score '{score_str}' to float for finding '{title}'.")
                if isinstance(vuln_name, str) and vuln_name.upper().startswith("CVE-"):
                    finding.cve = vuln_name
                findings_list.append(finding)
        return findings_list

    @staticmethod
    def parse_secrets(secrets_data, test):
        """Parses secret findings into granular DefectDojo findings."""
        findings_list = []
        if not secrets_data:
            return findings_list
        for secret in secrets_data:
            secret_description = secret.get("description", "Secret detected")
            secret_type = secret.get("type", "UNKNOWN_TYPE")
            file_path = secret.get("path", "N/A")
            line_number = secret.get("lineNumber")
            severity_str = secret.get("severity")
            severity = WizcliParsers.get_severity(severity_str)
            title = f"Secret Detected: {secret_description} ({secret_type})"
            description_parts = [
                f"**Type**: `{secret_type}`",
                f"**Description**: {secret_description}",
                f"**File**: `{file_path}`",
            ]
            if line_number is not None:
                description_parts.append(f"**Line**: {line_number}")
            details = secret.get("details", {})
            detail_type = details.get("__typename")
            if detail_type == "DiskScanSecretDetailsPassword":
                description_parts.append("\n**Password Details**:")
                if (pw_len := details.get("length")) is not None:
                    description_parts.append(f"- Length: {pw_len}")
                if (is_complex := details.get("isComplex")) is not None:
                    description_parts.append(f"- Complex: {is_complex}")
            elif detail_type == "DiskScanSecretDetailsCloudKey":
                description_parts.append("\n**Cloud Key Details**:")
                if (provider_id := details.get("providerUniqueID")):
                    description_parts.append(f"- Provider Unique ID: {provider_id}")
                if (key_type_num := details.get("keyType")) is not None:
                    description_parts.append(f"- Key Type Code: {key_type_num}")
                if (is_long_term := details.get("isLongTerm")) is not None:
                    description_parts.append(f"- Long Term Key: {is_long_term}")

            failed_policies = secret.get("failedPolicyMatches", [])
            if failed_policies:
                description_parts.append("\n**Failed Policies**:")
                for match in failed_policies:
                    policy = match.get("policy", {})
                    description_parts.append(f"- {policy.get('name', 'N/A')} (ID: {policy.get('id', 'N/A')})")

            full_description = "\n".join(description_parts)
            mitigation = "Rotate the exposed secret immediately. Remove the secret from the specified file path and line. Store secrets securely using a secrets management solution. Review commit history."

            # Generate unique ID using stable components
            unique_id = WizcliParsers._generate_unique_id(
                [secret_type, file_path, str(line_number) if line_number is not None else "0"],
            )

            finding = Finding(
                test=test,
                title=title,
                description=full_description,
                severity=severity,
                mitigation=mitigation,
                file_path=file_path,
                line=line_number if line_number is not None else 0,
                static_finding=True,
                dynamic_finding=False,
                unique_id_from_tool=unique_id,
                active=True,  # Always set as active since we don't have status from Wiz
            )
            findings_list.append(finding)
        return findings_list

    @staticmethod
    def parse_os_packages(os_packages_data, test):
        """Parses OS package vulnerabilities into granular DefectDojo findings."""
        findings_list = []
        if not os_packages_data:
            return findings_list
        for os_pkg in os_packages_data:
            pkg_name = os_pkg.get("name", "N/A")
            pkg_version = os_pkg.get("version", "N/A")
            vulnerabilities = os_pkg.get("vulnerabilities", [])
            if not vulnerabilities:
                continue
            for vuln_data in vulnerabilities:
                vuln_name = vuln_data.get("name", "N/A")
                severity_str = vuln_data.get("severity")
                severity = WizcliParsers.get_severity(severity_str)
                fixed_version = vuln_data.get("fixedVersion")
                source_url = vuln_data.get("source", "N/A")
                vuln_description_from_wiz = vuln_data.get("description")
                score_str = vuln_data.get("score")
                has_exploit = vuln_data.get("hasExploit", False)
                has_cisa_kev_exploit = vuln_data.get("hasCisaKevExploit", False)
                title = f"OS Pkg: {pkg_name} {pkg_version} - {vuln_name}"
                description_parts = [
                    f"**Vulnerability**: `{vuln_name}`",
                    f"**Severity**: {severity}",
                    f"**OS Package**: `{pkg_name}`",
                    f"**Version**: `{pkg_version}`",
                ]
                if fixed_version:
                    description_parts.append(f"**Fixed Version**: {fixed_version}")
                    mitigation = f"Update OS package `{pkg_name}` to version `{fixed_version}` or later."
                else:
                    description_parts.append("**Fixed Version**: N/A")
                    mitigation = f"Patch or update OS package `{pkg_name}` as per vendor advisory for `{vuln_name}`."
                description_parts.append(f"**Source**: {source_url}")
                if vuln_description_from_wiz:
                    description_parts.append(f"\n**Details from Wiz**:\n{vuln_description_from_wiz}\n")
                if score_str is not None:
                    description_parts.append(f"**CVSS Score (from Wiz)**: {score_str}")
                description_parts.extend([
                    f"**Has Exploit (Known)**: {has_exploit}",
                    f"**In CISA KEV**: {has_cisa_kev_exploit}",
                ])
                failed_policies = vuln_data.get("failedPolicyMatches", [])
                if failed_policies:
                    description_parts.append("\n**Failed Policies**:")
                    for match in failed_policies:
                        policy = match.get("policy", {})
                        description_parts.append(f"- {policy.get('name', 'N/A')} (ID: {policy.get('id', 'N/A')})")
                ignored_policies = vuln_data.get("ignoredPolicyMatches", [])
                if ignored_policies:
                    description_parts.append("\n**Ignored Policies**:")
                    for match in ignored_policies:
                        policy = match.get("policy", {})
                        description_parts.append(f"- {policy.get('name', 'N/A')} (ID: {policy.get('id', 'N/A')})")

                full_description = "\n".join(description_parts)
                references = source_url if source_url != "N/A" else None

                # Generate unique ID using stable components
                unique_id = WizcliParsers._generate_unique_id(
                    [pkg_name, pkg_version, vuln_name],
                )

                finding = Finding(
                    test=test,
                    title=title,
                    description=full_description,
                    severity=severity,
                    mitigation=mitigation,
                    static_finding=True,
                    dynamic_finding=False,
                    unique_id_from_tool=unique_id,
                    vuln_id_from_tool=vuln_name,
                    references=references,
                    active=True,  # Always set as active since we don't have status from Wiz
                )
                if score_str is not None:
                    try:
                        finding.cvssv3_score = float(score_str)
                    except (ValueError, TypeError):
                        logger.warning(f"Could not convert score '{score_str}' to float for finding '{title}'.")
                if isinstance(vuln_name, str) and vuln_name.upper().startswith("CVE-"):
                    finding.cve = vuln_name
                findings_list.append(finding)
        return findings_list

    @staticmethod
    def parse_rule_matches(rule_matches_data, test):
        """
        Parses IaC rule match data into granular DefectDojo findings.
        Creates one finding per rule match instance on a specific resource.
        """
        findings_list = []
        if not rule_matches_data:
            logger.debug("No ruleMatches data found to parse.")
            return findings_list

        for rule_match in rule_matches_data:
            rule = rule_match.get("rule", {})
            rule_id = rule.get("id", "N/A")
            rule_name = rule.get("name", "Unnamed Rule")
            # Use the severity from the ruleMatch level
            severity_str = rule_match.get("severity")
            severity = WizcliParsers.get_severity(severity_str)

            matches = rule_match.get("matches", [])
            if not matches:
                continue

            for match in matches:
                resource_name = match.get("resourceName", "N/A")
                file_name = match.get("fileName", "N/A")
                line_number = match.get("lineNumber")  # Can be None or int
                match_content = match.get("matchContent", "N/A")  # Code snippet
                expected = match.get("expected", "N/A")
                found = match.get("found", "N/A")
                file_type = match.get("fileType", "IaC")  # e.g., TERRAFORM, KUBERNETES
                remediation = match.get("remediationInstructions")  # Can be None

                # Title: IaC: Rule Name - Resource Name (e.g., IaC: S3 Bucket Logging Disabled - my-bucket)
                title = f"{rule_name} - {resource_name}"

                # Description
                description_parts = [
                    f"**Rule**: {rule_name} (ID: `{rule_id}`)",
                    f"**Severity**: {severity}",
                    f"**Resource**: `{resource_name}`",
                    f"**File**: `{file_name}`",
                ]
                if line_number is not None:
                    description_parts.append(f"**Line**: {line_number}")
                if match_content and match_content != "N/A":
                    description_parts.append(f"**Code Snippet**: ```\n{match_content}\n```")  # Use markdown code block

                description_parts.extend([
                    "\n**Finding Details**:",
                    f"- **Expected**: {expected}",
                    f"- **Found**: {found}",
                    f"- **File Type**: {file_type}",
                ])

                # Use remediationInstructions as mitigation and potentially extract reference
                mitigation = remediation or "Refer to Wiz rule details and vendor documentation."
                references = WizcliParsers.extract_reference_link(remediation)

                # Policy Information (from match level first, then rule level)
                match_failed_policies = match.get("failedPolicies", [])
                rule_failed_policies = rule_match.get("failedPolicyMatches", [])  # Top level rule match policies
                if match_failed_policies or rule_failed_policies:
                    description_parts.append("\n**Failed Policies**:")
                    processed_policy_ids = set()
                    for pol_match in match_failed_policies + rule_failed_policies:
                        policy = pol_match.get("policy", {})
                        pol_id = policy.get("id")
                        if pol_id and pol_id not in processed_policy_ids:
                            description_parts.append(f"- {policy.get('name', 'N/A')} (ID: {pol_id})")
                            processed_policy_ids.add(pol_id)

                match_ignored_policies = match.get("ignoredPolicyMatches", [])
                rule_ignored_policies = []  # Ignored policies seem to only be at the match level in the sample
                if match_ignored_policies or rule_ignored_policies:
                    description_parts.append("\n**Ignored Policies**:")
                    processed_policy_ids = set()
                    for pol_match in match_ignored_policies + rule_ignored_policies:
                        policy = pol_match.get("policy", {})
                        pol_id = policy.get("id")
                        reason = pol_match.get("ignoreReason", "N/A")
                        if pol_id and pol_id not in processed_policy_ids:
                            description_parts.append(f"- {policy.get('name', 'N/A')} (ID: {pol_id}), Reason: {reason}")
                            processed_policy_ids.add(pol_id)

                full_description = "\n".join(description_parts)

                # Generate unique ID using stable components for IAC
                unique_id = WizcliParsers._generate_unique_id(
                    [rule_id, resource_name, file_name, str(line_number) if line_number is not None else "0"],  # Only use rule ID and resource name for deduplication
                )

                finding = Finding(
                    test=test,
                    title=title,
                    description=full_description,
                    severity=severity,
                    mitigation=mitigation,
                    file_path=file_name,
                    line=line_number if line_number is not None else 0,
                    component_name=resource_name,  # Use resource name as component
                    static_finding=True,
                    dynamic_finding=False,
                    unique_id_from_tool=unique_id,
                    vuln_id_from_tool=rule_id,  # Use rule ID as the identifier
                    references=references,
                    active=True,  # Always set as active since we don't have status from Wiz
                )
                findings_list.append(finding)

        return findings_list

    @staticmethod
    def convert_status(wiz_status) -> dict:
        """Convert the Wiz Status to a dict of Finding status flags."""
        if (status := wiz_status) is not None:
            if status.upper() == "OPEN":
                return {"active": True}
            if status.upper() == "RESOLVED":
                return {"active": False, "is_mitigated": True}
            if status.upper() == "IGNORED":
                return {"active": False, "out_of_scope": True}
            if status.upper() == "IN_PROGRESS":
                return {"active": True}
        return {"active": True}
