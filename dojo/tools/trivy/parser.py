"""Parser for Aquasecurity trivy (https://github.com/aquasecurity/trivy) Docker images scaner"""

import json
import logging

from dojo.models import Finding
from dojo.utils import parse_cvss_data

logger = logging.getLogger(__name__)


TRIVY_SEVERITIES = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "UNKNOWN": "Info",
}

CVSS_SEVERITY_SOURCES = [
    "nvd",
    "ghsa",
    "redhat",
    "bitnami",
]

DESCRIPTION_TEMPLATE = """{title}
**Target:** {target}
**Type:** {type}
**Fixed version:** {fixed_version}

{description_text}
"""

MISC_DESCRIPTION_TEMPLATE = """**Target:** {target}
**Type:** {type}

{description}
{message}
"""

SECRET_DESCRIPTION_TEMPLATE = """{title}
**Category:** {category}
**Match:** {match}
"""  # noqa: S105

LICENSE_DESCRIPTION_TEMPLATE = """{title}
**Category:** {category}
**Package:** {package}
"""


class TrivyParser:
    def get_scan_types(self):
        return ["Trivy Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Trivy Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import trivy JSON scan report."

    def convert_cvss_score(self, raw_value):
        if raw_value is None:
            return "Info"
        val = float(raw_value)
        if val == 0.0:
            return "Info"
        if val < 4.0:
            return "Low"
        if val < 7.0:
            return "Medium"
        if val < 9.0:
            return "High"
        return "Critical"

    def convert_trivy_status(self, trivy_status: str) -> dict:
        """
        Determine status fields based on Trivy status

        From: https://trivy.dev/v0.54/docs/configuration/filtering/

        Trivy has a Status field based on VEX vulnerability statuses. Please not these are statuses based on the vulnerability advisories by OS vendors such as Debian, RHEL, etc.

        - `unknown`
        - `not_affected`: this package is not affected by this vulnerability on this platform
        - `affected`: this package is affected by this vulnerability on this platform, but there is no patch released yet
        - `fixed`: this vulnerability is fixed on this platform
        - `under_investigation`: it is currently unknown whether or not this vulnerability affects this package on this platform, and it is under investigation
        - `will_not_fix`: this package is affected by this vulnerability on this platform, but there is currently no intention to fix it (this would primarily be for flaws that are of Low or Moderate impact that pose no significant risk to customers)
        - `fix_deferred`: this package is affected by this vulnerability on this platform, and may be fixed in the future
        - `end_of_life`: this package has been identified to contain the impacted component, but analysis to determine whether it is affected or not by this vulnerability was not performed


        Note that vulnerabilities with the `unknown`, `not_affected` or `under_investigation` status are not detected.
        These are only defined for comprehensiveness, and you will not have the opportunity to specify these statuses.

        Some statuses are supported in limited distributions.

        |     OS     | Fixed | Affected | Under Investigation | Will Not Fix | Fix Deferred | End of Life |
        |:----------:|:-----:|:--------:|:-------------------:|:------------:|:------------:|:-----------:|
        |   Debian   |   ✓   |    ✓     |                     |              |      ✓       |      ✓      |
        |    RHEL    |   ✓   |    ✓     |          ✓          |      ✓       |      ✓       |      ✓      |
        | Other OSes |   ✓   |    ✓     |                     |              |              |             |
        """
        status_mapping = {
            "unknown": {
                # use default value for active which is usually True
                "verified": False,
            },
            "not_affected": {
                # false positive is the most appropriate status for not affected as out of scope might be interpreted as something else
                "active": False,
                "verified": True,
                "is_mitigated": True,
            },
            "affected": {
                # standard case
                "active": True,
                "verified": True,
            },
            "fixed": {
                # fixed in this context means that there is a fix available by patching/updating/upgrading the package
                # but it's still active and verified
                "active": True,
                "verified": True,
            },
            "under_investigation": {
                # no status flag in Defect Dojo to capture this, but verified is False
                "active": True,
                "verified": False,
            },
            "will_not_fix": {
                # no different from affected as Defect Dojo doesn't have a flag to capture will_not_fix by OS/Package Vendor
                # we can't set active to False as the user needs to risk accept this finding
                "active": True,
                "verified": True,
            },
            "fix_deferred": {
                # no different from affected as Defect Dojo doesn't have a flag to capture will_not_fix by OS/Package Vendor
                # we can't set active to False as the user needs to (temporarily) risk accept this finding
                "active": True,
                "verified": True,
            },
            "end_of_life": {
                # no different from affected as Defect Dojo doesn't have a flag to capture will_not_fix by OS/Package Vendor
                # we can't set active to False as the user needs to (temporarily) risk accept this finding
                "active": True,
                "verified": True,
            },
        }

        # default is to fallback to default Defect Dojo behaviour which takes scan parameters into account
        return status_mapping.get(trivy_status, {})

    def get_findings(self, scan_file, test):
        scan_data = scan_file.read()

        try:
            data = json.loads(str(scan_data, "utf-8"))
        except Exception:
            data = json.loads(scan_data)

        # Legacy format is empty
        if data is None:
            return []
        # Legacy format with results
        if isinstance(data, list):
            return self.get_result_items(test, data)
        schema_version = data.get("SchemaVersion", None)
        artifact_name = data.get("ArtifactName", "")
        cluster_name = data.get("ClusterName")
        if schema_version == 2:
            results = data.get("Results", [])
            return self.get_result_items(test, results, artifact_name=artifact_name)
        if cluster_name is not None:
            findings = []
            vulnerabilities = data.get("Vulnerabilities", [])
            for service in vulnerabilities:
                namespace = service.get("Namespace")
                kind = service.get("Kind")
                name = service.get("Name")
                service_name = ""
                if namespace:
                    service_name = f"{namespace} / "
                if kind:
                    service_name += f"{kind} / "
                if name:
                    service_name += f"{name} / "
                if len(service_name) >= 3:
                    service_name = service_name[:-3]
                findings += self.get_result_items(
                    test, service.get("Results", []), service_name,
                )
            misconfigurations = data.get("Misconfigurations", [])
            for service in misconfigurations:
                namespace = service.get("Namespace")
                kind = service.get("Kind")
                name = service.get("Name")
                service_name = ""
                if namespace:
                    service_name = f"{namespace} / "
                if kind:
                    service_name += f"{kind} / "
                if name:
                    service_name += f"{name} / "
                if len(service_name) >= 3:
                    service_name = service_name[:-3]
                findings += self.get_result_items(
                    test, service.get("Results", []), service_name,
                )
            resources = data.get("Resources", [])
            for resource in resources:
                namespace = resource.get("Namespace")
                kind = resource.get("Kind")
                name = resource.get("Name")
                if namespace:
                    resource_name = f"{namespace} / "
                if kind:
                    resource_name += f"{kind} / "
                if name:
                    resource_name += f"{name} / "
                if len(resource_name) >= 3:
                    resource_name = resource_name[:-3]
                findings += self.get_result_items(
                    test, resource.get("Results", []), resource_name,
                )
            return findings
        msg = "Schema of Trivy json report is not supported"
        raise ValueError(msg)

    def get_result_items(self, test, results, service_name=None, artifact_name=""):
        items = []
        for target_data in results:
            if (
                not isinstance(target_data, dict)
                or "Target" not in target_data
            ):
                continue
            target = target_data["Target"]

            target_target = target_data.get("Target")
            target_class = target_data.get("Class")
            target_type = target_data.get("Type")

            vulnerabilities = target_data.get("Vulnerabilities", []) or []
            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                try:
                    vuln_id = vuln.get("VulnerabilityID", "0")
                    package_name = vuln["PkgName"]
                    detected_severity_source = vuln.get("SeveritySource", None)
                    cvss = vuln.get("CVSS", {})
                    cvssclass = None
                    cvssv3 = None
                    cvssv3_score = None
                    # Iterate over the possible severity sources tom find the first match
                    for severity_source in [detected_severity_source, *CVSS_SEVERITY_SOURCES]:
                        cvssclass = cvss.get(severity_source, None)
                        if cvssclass is not None:
                            break
                    # Parse the CVSS class if it is not None
                    if cvssclass is not None:
                        if cvss_data := parse_cvss_data(cvssclass.get("V3Vector", "")):
                            cvssv3 = cvss_data.get("cvssv3")
                            cvssv3_score = cvss_data.get("cvssv3_score")
                            severity = cvss_data.get("severity")
                        elif (cvss_v3_score := cvssclass.get("V3Score")) is not None:
                            cvssv3_score = cvss_v3_score
                            severity = self.convert_cvss_score(cvss_v3_score)
                        elif (cvss_v2_score := cvssclass.get("V2Score")) is not None:
                            severity = self.convert_cvss_score(cvss_v2_score)
                        else:
                            severity = self.convert_cvss_score(None)
                    else:
                        severity = TRIVY_SEVERITIES[vuln["Severity"]]
                    if target_class in {"os-pkgs", "lang-pkgs"}:
                        file_path = vuln.get("PkgPath")
                        if file_path is None:
                            file_path = target_target
                    elif target_class == "config":
                        file_path = target_target
                    else:
                        file_path = None
                except KeyError as exc:
                    logger.warning("skip vulnerability due %r", exc)
                    continue
                package_version = vuln.get("InstalledVersion", "")
                references = "\n".join(vuln.get("References", []))
                mitigation = vuln.get("FixedVersion", "")
                fix_available = True
                if mitigation == "":
                    fix_available = False
                impact = vuln.get("Status", "")
                status_fields = self.convert_trivy_status(vuln.get("Status", ""))
                cwe = int(vuln["CweIDs"][0].split("-")[1]) if len(vuln.get("CweIDs", [])) > 0 else 0
                vul_type = target_data.get("Type", "")
                title = f"{vuln_id} {package_name} {package_version}"
                description = DESCRIPTION_TEMPLATE.format(
                    title=vuln.get("Title", ""),
                    target=target,
                    type=vul_type,
                    fixed_version=mitigation,
                    description_text=vuln.get("Description", ""),
                )
                finding = Finding(
                    test=test,
                    title=title,
                    cwe=cwe,
                    severity=severity,
                    file_path=file_path,
                    references=references,
                    description=description,
                    impact=impact,
                    mitigation=mitigation,
                    component_name=package_name,
                    component_version=package_version,
                    cvssv3=cvssv3,
                    cvssv3_score=cvssv3_score,
                    static_finding=True,
                    dynamic_finding=False,
                    fix_available=fix_available,
                    tags=[vul_type, target_class],
                    service=service_name,
                    **status_fields,
                )

                if vuln_id:
                    finding.unsaved_vulnerability_ids = [vuln_id]

                items.append(finding)

            misconfigurations = target_data.get("Misconfigurations", [])
            for misconfiguration in misconfigurations:
                misc_type = misconfiguration.get("Type")
                misc_id = misconfiguration.get("ID")
                misc_title = misconfiguration.get("Title")
                misc_description = misconfiguration.get("Description")
                misc_message = misconfiguration.get("Message")
                misc_resolution = misconfiguration.get("Resolution")
                misc_severity = misconfiguration.get("Severity")
                misc_primary_url = misconfiguration.get("PrimaryURL")
                misc_references = misconfiguration.get("References", [])
                misc_causemetadata = misconfiguration.get("CauseMetadata", {})
                misc_cause_code = misc_causemetadata.get("Code", {})
                misc_cause_lines = misc_cause_code.get("Lines", [])
                string_lines_table = self.get_lines_as_string_table(misc_cause_lines)
                if string_lines_table != "":
                    misc_message += ("\n" + string_lines_table)

                title = f"{misc_id} - {misc_title}"
                description = MISC_DESCRIPTION_TEMPLATE.format(
                    target=target_target,
                    type=misc_type,
                    description=misc_description,
                    message=misc_message,
                )
                severity = TRIVY_SEVERITIES[misc_severity]
                references = None
                if misc_primary_url:
                    references = f"{misc_primary_url}\n"
                if misc_primary_url in misc_references:
                    misc_references.remove(misc_primary_url)
                if references:
                    references += "\n".join(misc_references)
                else:
                    references = "\n".join(misc_references)

                finding = Finding(
                    test=test,
                    title=title,
                    severity=severity,
                    references=references,
                    description=description,
                    mitigation=misc_resolution,
                    fix_available=True,
                    static_finding=True,
                    dynamic_finding=False,
                    tags=[target_type, target_class],
                    service=service_name,
                )
                items.append(finding)

            secrets = target_data.get("Secrets", [])
            for secret in secrets:
                secret_category = secret.get("Category")
                secret_title = secret.get("Title")
                secret_severity = secret.get("Severity")
                secret_match = secret.get("Match")
                secret_start_line = secret.get("StartLine")

                title = f"Secret detected in {target_target} - {secret_title}"
                description = SECRET_DESCRIPTION_TEMPLATE.format(
                    title=secret_title,
                    category=secret_category,
                    match=secret_match,
                )
                severity = TRIVY_SEVERITIES[secret_severity]

                finding = Finding(
                    test=test,
                    title=title,
                    severity=severity,
                    description=description,
                    file_path=target_target,
                    line=secret_start_line,
                    static_finding=True,
                    dynamic_finding=False,
                    fix_available=True,
                    tags=[target_class],
                    service=service_name,
                )
                items.append(finding)

            licenses = target_data.get("Licenses", [])
            for lic in licenses:
                license_severity = lic.get("Severity")
                license_category = lic.get("Category")
                license_pkgname = lic.get("PkgName")
                license_filepath = lic.get("FilePath")
                license_name = lic.get("Name")
                license_confidence = lic.get("Confidence")
                license_link = lic.get("Link")

                title = f"License detected in {target_target} - {license_name}"
                description = LICENSE_DESCRIPTION_TEMPLATE.format(
                    title=license_name,
                    category=license_category,
                    package=license_pkgname,
                )
                severity = TRIVY_SEVERITIES[license_severity]

                finding = Finding(
                    test=test,
                    title=title,
                    severity=severity,
                    description=description,
                    file_path=license_filepath,
                    scanner_confidence=license_confidence,
                    url=license_link,
                    static_finding=True,
                    dynamic_finding=False,
                    fix_available=True,
                    tags=[target_class],
                    service=service_name,
                )
                items.append(finding)

        return items

    def get_lines_as_string_table(self, lines):
        if lines is None:
            return ""
        # Define column headers
        headers = ["Number", "Content"]

        # Create the header row
        header_row = "\t".join(headers)

        # Create the table string
        table_string = f"{header_row}\n"
        for item in lines:
            row = "\t".join(str(item.get(header, "")) for header in headers)
            table_string += f"{row}\n"

        return table_string
