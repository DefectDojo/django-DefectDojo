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

                    finding_description = (
                        f"**Library Name**: {lib_name}\n"
                        f"**Library Version**: {lib_version}\n"
                        f"**Library Path**: {lib_path}\n"
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
