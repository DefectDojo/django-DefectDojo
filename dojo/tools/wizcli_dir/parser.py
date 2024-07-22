import json
from dojo.models import Finding

class WizcliDirParser:
    def get_scan_types(self):
        return ["Wizcli Dir Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Wizcli Dir Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Wizcli Dir Scan results in JSON file format."

    def parse_libraries(self, libraries, test):
        findings = []
        if libraries:
            for library in libraries:
                lib_name = library.get("name", "N/A")
                lib_version = library.get("version", "N/A")
                lib_path = library.get("path", "N/A")
                vulnerabilities = library.get("vulnerabilities", [])

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

    def parse_secrets(self, secrets, test):
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

    def get_findings(self, filename, test):
        scan_data = filename.read()
        try:
            data = json.loads(scan_data.decode("utf-8"))
        except Exception:
            data = json.loads(scan_data)
        findings = []
        results = data.get("result", {})

        libraries = results.get("libraries", None)
        if libraries:
            findings.extend(self.parse_libraries(libraries, test))

        secrets = results.get("secrets", None)
        if secrets:
            findings.extend(self.parse_secrets(secrets, test))

        return findings
