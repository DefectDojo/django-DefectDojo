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
                        title=f"{lib_name} - {vuln_name}",
                        description=finding_description,
                        file_path=lib_path,
                        severity=severity,
                        static_finding=True,
                        dynamic_finding=False,
                        mitigation=None,
                        test=test,
                    )
                    findings.append(finding)
        return findings

    @staticmethod
    def parse_secrets(secrets, test):
        findings = []
        if secrets:
            for secret in secrets:
                secret_id = secret.get("id", "N/A")
                desc = secret.get("description", "N/A")
                severity = "High"
                file_name = secret.get("path", "N/A")
                line_number = secret.get("lineNumber", "N/A")
                match_content = secret.get("type", "N/A")

                description = (
                    f"**Secret ID**: {secret_id}\n"
                    f"**Description**: {desc}\n"
                    f"**File Name**: {file_name}\n"
                    f"**Line Number**: {line_number}\n"
                    f"**Match Content**: {match_content}\n"
                )

                finding = Finding(
                    title=f"Secret: {desc}",
                    description=description,
                    severity=severity,
                    file_path=file_name,
                    line=line_number,
                    static_finding=True,
                    dynamic_finding=False,
                    mitigation=None,
                    test=test,
                )
                findings.append(finding)
        return findings

    @staticmethod
    def parse_rule_matches(rule_matches, test):
        findings = []
        if rule_matches:
            for rule_match in rule_matches:
                rule = rule_match.get("rule", {})
                rule_id = rule.get("id", "N/A")
                rule_name = rule.get("name", "N/A")
                severity = rule_match.get("severity", "low").lower().capitalize()

                matches = rule_match.get("matches", [])
                if matches:
                    for match in matches:
                        resource_name = match.get("resourceName", "N/A")
                        file_name = match.get("fileName", "N/A")
                        line_number = match.get("lineNumber", "N/A")
                        match_content = match.get("matchContent", "N/A")
                        expected = match.get("expected", "N/A")
                        found = match.get("found", "N/A")
                        file_type = match.get("fileType", "N/A")

                        description = (
                            f"**Rule ID**: {rule_id}\n"
                            f"**Rule Name**: {rule_name}\n"
                            f"**Resource Name**: {resource_name}\n"
                            f"**File Name**: {file_name}\n"
                            f"**Line Number**: {line_number}\n"
                            f"**Match Content**: {match_content}\n"
                            f"**Expected**: {expected}\n"
                            f"**Found**: {found}\n"
                            f"**File Type**: {file_type}\n"
                        )

                        finding = Finding(
                            title=f"{rule_name} - {resource_name}",
                            description=description,
                            severity=severity,
                            file_path=file_name,
                            line=line_number,
                            static_finding=True,
                            dynamic_finding=False,
                            mitigation=None,
                            test=test,
                        )
                        findings.append(finding)
        return findings

    @staticmethod
    def parse_os_packages(osPackages, test):
        findings = []
        if osPackages:
            for osPackage in osPackages:
                pkg_name = osPackage.get("name", "N/A")
                pkg_version = osPackage.get("version", "N/A")
                vulnerabilities = osPackage.get("vulnerabilities", [])

                for vulnerability in vulnerabilities:
                    vuln_name = vulnerability.get("name", "N/A")
                    severity = vulnerability.get("severity", "low").lower().capitalize()
                    fixed_version = vulnerability.get("fixedVersion", "N/A")
                    source = vulnerability.get("source", "N/A")
                    description = vulnerability.get("description", "N/A")
                    score = vulnerability.get("score", "N/A")
                    exploitability_score = vulnerability.get("exploitabilityScore", "N/A")
                    has_exploit = vulnerability.get("hasExploit", False)
                    has_cisa_kev_exploit = vulnerability.get("hasCisaKevExploit", False)

                    finding_description = (
                        f"**OS Package Name**: {pkg_name}\n"
                        f"**OS Package Version**: {pkg_version}\n"
                        f"**Vulnerability Name**: {vuln_name}\n"
                        f"**Fixed Version**: {fixed_version}\n"
                        f"**Source**: {source}\n"
                        f"**Description**: {description}\n"
                        f"**Score**: {score}\n"
                        f"**Exploitability Score**: {exploitability_score}\n"
                        f"**Has Exploit**: {has_exploit}\n"
                        f"**Has CISA KEV Exploit**: {has_cisa_kev_exploit}\n"
                    )

                    finding = Finding(
                        title=f"{pkg_name} - {vuln_name}",
                        description=finding_description,
                        severity=severity,
                        static_finding=True,
                        dynamic_finding=False,
                        mitigation=None,
                        test=test,
                    )
                    findings.append(finding)
        return findings
