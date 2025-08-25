import json
import logging

from cvss import parser as cvss_parser
from cvss.cvss3 import CVSS3

from dojo.models import Finding

logger = logging.getLogger(__name__)


class AnchoreGrypeParser:

    """
    Anchore Grype JSON report format generated with `-o json` option.

    command: `grype defectdojo/defectdojo-django:1.13.1 -o json > many_vulns.json`
    """

    def get_scan_types(self):
        return ["Anchore Grype"]

    def get_label_for_scan_types(self, scan_type):
        return "Anchore Grype"

    def get_description_for_scan_types(self, scan_type):
        return (
            "A vulnerability scanner for container images, filesystems, and SBOMs. "
            "JSON report generated with '--output=json' format."
        )

    def get_findings(self, file, test):
        logger.debug(f"file: {file}")
        data = json.load(file)
        logger.debug(f"data: {data}")
        dupes = {}
        for item in data.get("matches", []):
            vulnerability = item["vulnerability"]
            vuln_id = vulnerability["id"]
            vuln_namespace = vulnerability.get("namespace")
            vuln_datasource = vulnerability.get("dataSource")
            vuln_severity = self._convert_severity(vulnerability.get("severity", "Info"))
            vuln_urls = vulnerability.get("urls")
            vuln_description = vulnerability.get("description")
            vuln_fix_versions = None
            if "fix" in vulnerability:
                vuln_fix_versions = vulnerability["fix"].get("versions")
            vuln_cvss = vulnerability.get("cvss")
            vuln_epss = vulnerability.get("epss")

            rel_datasource = None
            rel_urls = None
            rel_description = None
            rel_cvss = None
            rel_epss = None
            vulnerability_ids = None
            related_vulnerabilities = item.get("relatedVulnerabilities")
            if related_vulnerabilities:
                related_vulnerability = related_vulnerabilities[0]
                rel_datasource = related_vulnerability.get("dataSource")
                rel_urls = related_vulnerability.get("urls")
                rel_description = related_vulnerability.get("description")
                rel_cvss = related_vulnerability.get("cvss")
                rel_epss = related_vulnerability.get("epss")
                rel_vuln_id = related_vulnerability.get("id")
            vulnerability_ids = self.get_vulnerability_ids(
                vuln_id, related_vulnerabilities,
            )

            matches = item["matchDetails"]

            artifact = item["artifact"]
            artifact_name = artifact.get("name")
            artifact_version = artifact.get("version")
            artifact_purl = artifact.get("purl")
            artifact_location = artifact.get("locations")
            file_path = None
            if (
                artifact_location
                and len(artifact_location) > 0
                and artifact_location[0].get("path")
            ):
                file_path = artifact_location[0].get("path")

            finding_title = f"{vuln_id} in {artifact_name}:{artifact_version}"

            finding_tags = None
            finding_description = ""
            if vuln_namespace:
                finding_description += (
                    f"**Vulnerability Namespace:** {vuln_namespace}"
                )
            if vuln_description:
                finding_description += (
                    f"\n**Vulnerability Description:** {vuln_description}"
                )
            if rel_description and rel_description != vuln_description:
                finding_description += f"\n**Related Vulnerability Description:** {rel_description}"
            if matches:
                if isinstance(item["matchDetails"], dict):
                    finding_description += (
                        f"\n**Matcher:** {matches['matcher']}"
                    )
                    finding_tags = [matches["matcher"].replace("-matcher", "")]
                elif len(matches) == 1:
                    finding_description += (
                        f"\n**Matcher:** {matches[0]['matcher']}"
                    )
                    finding_tags = [
                        matches[0]["matcher"].replace("-matcher", ""),
                    ]
                else:
                    finding_description += "\n**Matchers:**"
                    finding_tags = []
                    for match in matches:
                        finding_description += f"\n- {match['matcher']}"
                        tag = match["matcher"].replace("-matcher", "")
                        if tag not in finding_tags:
                            finding_tags.append(tag)
            if artifact_purl:
                finding_description += f"\n**Package URL:** {artifact_purl}"

            finding_mitigation = None
            if vuln_fix_versions:
                finding_mitigation = "Upgrade to version:"
                if len(vuln_fix_versions) == 1:
                    finding_mitigation += f" {vuln_fix_versions[0]}"
                else:
                    for fix_version in vuln_fix_versions:
                        finding_mitigation += f"\n- {fix_version}"

            finding_references = ""
            if vuln_datasource:
                finding_references += (
                    f"**Vulnerability Datasource:** {vuln_datasource}\n"
                )
            if vuln_urls:
                if len(vuln_urls) == 1:
                    if vuln_urls[0] != vuln_datasource:
                        finding_references += (
                            f"**Vulnerability URL:** {vuln_urls[0]}\n"
                        )
                else:
                    finding_references += "**Vulnerability URLs:**\n"
                    for url in vuln_urls:
                        if url != vuln_datasource:
                            finding_references += f"- {url}\n"
            if rel_datasource:
                finding_references += (
                    f"**Related Vulnerability Datasource:** {rel_datasource}\n"
                )
            if rel_urls:
                if len(rel_urls) == 1:
                    if rel_urls[0] != vuln_datasource:
                        finding_references += (
                            f"**Related Vulnerability URL:** {rel_urls[0]}\n"
                        )
                else:
                    finding_references += "**Related Vulnerability URLs:**\n"
                    for url in rel_urls:
                        if url != vuln_datasource:
                            finding_references += f"- {url}\n"
            if finding_references and finding_references[-1] == "\n":
                finding_references = finding_references[:-1]

            finding_cvss3 = None
            if vuln_cvss:
                finding_cvss3 = self.get_cvss(vuln_cvss)
            if not finding_cvss3 and rel_cvss:
                finding_cvss3 = self.get_cvss(rel_cvss)
            # https://github.com/DefectDojo/django-DefectDojo/issues/12819
            # the parser seems focues on only parsing the first related vulnerability
            # this fixes the mentioned github issue, but a more thorough rewrite might be needed
            # if the problem persists / we get more real world sample reports.
            finding_epss_score, finding_epss_percentile = self.get_epss_values(vuln_id, vuln_epss)
            if finding_epss_score is None and rel_epss:
                finding_epss_score, finding_epss_percentile = self.get_epss_values(rel_vuln_id, rel_epss)
                if finding_epss_score is None and rel_vuln_id:
                    finding_epss_score, finding_epss_percentile = self.get_epss_values(vuln_id, vuln_epss)

            dupe_key = finding_title
            if dupe_key in dupes:
                finding = dupes[dupe_key]
                finding.nb_occurences += 1
            else:
                dupes[dupe_key] = Finding(
                    title=finding_title.replace("\x00", ""),
                    description=finding_description.replace("\x00", ""),
                    cvssv3=finding_cvss3,
                    epss_score=finding_epss_score,
                    epss_percentile=finding_epss_percentile,
                    severity=vuln_severity,
                    mitigation=finding_mitigation,
                    references=finding_references,
                    component_name=artifact_name,
                    component_version=artifact_version.replace("\x00", ""),
                    vuln_id_from_tool=vuln_id,
                    tags=finding_tags,
                    static_finding=True,
                    dynamic_finding=False,
                    nb_occurences=1,
                    file_path=file_path,
                )
                dupes[dupe_key].unsaved_vulnerability_ids = vulnerability_ids

        return list(dupes.values())

    def _convert_severity(self, val):
        if val in {"Unknown", "Negligible"}:
            return "Info"
        return val.title()

    def get_cvss(self, cvss):
        if cvss:
            for cvss_item in cvss:
                vector = cvss_item["vector"]
                cvss_objects = cvss_parser.parse_cvss_from_text(vector)
                if len(cvss_objects) > 0 and isinstance(
                    cvss_objects[0], CVSS3,
                ):
                    return vector
        return None

    def get_epss_values(self, vuln_id, epss_list):
        if not isinstance(epss_list, list):
            logger.debug(f"epss_list is not a list: {epss_list}")
            return None, None

        if isinstance(epss_list, list):
            logger.debug(f"epss_list: {epss_list}")
            for epss_data in epss_list:
                if epss_data.get("cve") != vuln_id:
                    continue
                try:
                    epss_score = float(epss_data.get("epss"))
                    epss_percentile = float(epss_data.get("percentile"))
                except (TypeError, ValueError):
                    logger.debug(f"epss_data is not a float: {epss_data}")
                else:
                    return epss_score, epss_percentile
        logger.debug(f"epss not found for vuln_id: {vuln_id} in epss_list: {epss_list}")
        return None, None

    def get_vulnerability_ids(self, vuln_id, related_vulnerabilities):
        vulnerability_ids = []
        if vuln_id:
            vulnerability_ids.append(vuln_id)
        if related_vulnerabilities:
            vulnerability_ids.extend(related_vulnerability_id for related_vulnerability in related_vulnerabilities
                if (related_vulnerability_id := related_vulnerability.get("id")))
        if vulnerability_ids:
            return vulnerability_ids
        return None
