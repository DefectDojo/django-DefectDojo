import contextlib
import json
import logging

from dateutil import parser
from packaging.version import InvalidVersion, Version

from dojo.location.feature import locations_enabled
from dojo.models import Finding
from dojo.tools.locations import LocationData
from dojo.utils import parse_cvss_data

logger = logging.getLogger(__name__)


class DependencyTrackParser:

    def _convert_dependency_track_severity_to_dojo_severity(self, dependency_track_severity):
        """
        Converts a Dependency Track severity to a DefectDojo severity.
        :param dependency_track_severity: The severity from Dependency Track
        :return: A DefectDojo severity if a mapping can be found; otherwise a null value is returned
        """
        severity = dependency_track_severity.lower()
        if severity == "critical":
            return "Critical"
        if severity == "high":
            return "High"
        if severity == "medium":
            return "Medium"
        if severity == "low":
            return "Low"
        if severity.startswith("info"):
            return "Informational"
        return None

    def _component_version_in_range(self, component_version, affected_range):
        bound_fields = ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")
        if all(affected_range.get(field) is None for field in bound_fields):
            # No range bounds (for example an exact-version entry): it describes no band,
            # so it cannot be said to contain a version.
            return False
        try:
            version_start_including = affected_range.get("versionStartIncluding")
            if version_start_including is not None and component_version < Version(version_start_including):
                return False
            version_start_excluding = affected_range.get("versionStartExcluding")
            if version_start_excluding is not None and component_version <= Version(version_start_excluding):
                return False
            version_end_including = affected_range.get("versionEndIncluding")
            if version_end_including is not None and component_version > Version(version_end_including):
                return False
            version_end_excluding = affected_range.get("versionEndExcluding")
            if version_end_excluding is not None and component_version >= Version(version_end_excluding):
                return False
        except InvalidVersion:
            return False
        return True

    def _build_message(self, chosen_range):
        version_end_excluding = chosen_range.get("versionEndExcluding")
        if version_end_excluding is not None:
            return f"Upgrade to {version_end_excluding} or later"
        version_end_including = chosen_range.get("versionEndIncluding")
        if version_end_including is not None:
            return f"Upgrade to a version after {version_end_including}"
        return None

    def _derive_mitigation_from_affected_versions(self, dependency_track_finding):
        affected_versions = dependency_track_finding["vulnerability"].get("affectedVersions")
        if not affected_versions:
            return None
        component = dependency_track_finding.get("component", {})
        purl = component.get("purl")
        if purl is None:
            return None
        component_version = None
        component_version_string = component.get("version")
        if component_version_string is not None:
            with contextlib.suppress(InvalidVersion):
                component_version = Version(component_version_string)
        clean_purl = purl.rsplit("@", 1)[0]
        filtered_affected_ranges = [
            entry
            for entry in affected_versions
            if entry.get("identityType") == "PURL" and entry.get("identity") == clean_purl
        ]
        if not filtered_affected_ranges:
            return None
        chosen_range = None
        if component_version is None:
            # Without a comparable version we cannot choose between ranges; only a lone
            # range is unambiguous enough to act on.
            if len(filtered_affected_ranges) == 1:
                chosen_range = filtered_affected_ranges[0]
        else:
            for affected_range in filtered_affected_ranges:
                if self._component_version_in_range(component_version, affected_range):
                    chosen_range = affected_range
                    break
        if chosen_range is None:
            return None
        return self._build_message(chosen_range)

    def _convert_dependency_track_finding_to_dojo_finding(self, dependency_track_finding, test):
        """
        Converts a Dependency Track finding to a DefectDojo finding

        :param dependency_track_finding: A dictionary representing a single finding from a Dependency Track Finding Packaging Format (FPF) export
        :param test: The test that the DefectDojo finding should be associated to
        :return: A DefectDojo Finding model
        """
        # Validation of required fields
        if "vulnerability" not in dependency_track_finding:
            msg = "Missing 'vulnerability' node from finding!"
            raise ValueError(msg)
        if "vulnId" not in dependency_track_finding["vulnerability"]:
            msg = "Missing 'vulnId' node from vulnerability!"
            raise ValueError(msg)
        vuln_id = dependency_track_finding["vulnerability"]["vulnId"]
        if "source" not in dependency_track_finding["vulnerability"]:
            msg = "Missing 'source' node from vulnerability!"
            raise ValueError(msg)
        source = dependency_track_finding["vulnerability"]["source"]
        if "component" not in dependency_track_finding:
            msg = "Missing 'component' node from finding!"
            raise ValueError(msg)
        if "name" not in dependency_track_finding["component"]:
            msg = "Missing 'name' node from component!"
            raise ValueError(msg)
        component_name = dependency_track_finding["component"]["name"]

        # Build the title of the Dojo finding
        # Note: the 'version' of a component is not a requirement in the Dependency Track data model.
        # As such we only add in version information if it is present.
        if "version" in dependency_track_finding["component"] and dependency_track_finding["component"]["version"] is not None:
            component_version = dependency_track_finding["component"]["version"]
        else:
            component_version = None
        version_description = component_version if component_version is not None else ""

        title = f"{component_name}:{version_description} affected by: {vuln_id} ({source})"

        # Collect all vulnerability IDs: vulnId itself plus any aliases.
        # vuln_id is kept first because the first entry becomes the finding's primary
        # vulnerability id (its `cve`), and the aliases are sorted: they are collected in a set,
        # so emitting them in set order would let PYTHONHASHSEED decide both the primary id and
        # the order the ids are stored in.
        alias_sources = ("cveId", "sonatypeId", "ghsaId", "osvId", "snykId", "gsdId", "vulnDbId")
        aliases = set()
        for alias in dependency_track_finding["vulnerability"].get("aliases") or []:
            for alias_source in alias_sources:
                if alias_source in alias:
                    aliases.add(alias[alias_source])
        vulnerability_id = [vuln_id, *sorted(aliases - {vuln_id})]

        # Default CWE to CWE-1035 Using Components with Known Vulnerabilities if there is no CWE
        if "cweId" in dependency_track_finding["vulnerability"] and dependency_track_finding["vulnerability"]["cweId"] is not None:
            cwe = dependency_track_finding["vulnerability"]["cweId"]
        else:
            cwe = 1035

        # Build the description of the Dojo finding
        # We already know (from above) that the version information is not always present
        if component_version is not None:
            component_description = f"Version {component_version} of the {component_name} component"
        else:
            component_description = f"The {component_name} component"
        vulnerability_description = (
            "You are using a component with a known vulnerability. "
            f"{component_description} is affected by the vulnerability with an id of {vuln_id} as "
            f"identified by {source}."
        )
        # Append purl info if it is present
        if "purl" in dependency_track_finding["component"] and dependency_track_finding["component"]["purl"] is not None:
            component_purl = dependency_track_finding["component"]["purl"]
            vulnerability_description += f"\nThe purl of the affected component is: {component_purl}."
            # there is no file_path in the report, but defect dojo needs it otherwise it skips deduplication:
            # see https://github.com/DefectDojo/django-DefectDojo/issues/3647
            # might be no longer needed in the future, and is not needed if people use the default
            # hash code dedupe config for this parser
            file_path = component_purl
        else:
            file_path = "unknown"

        # Append other info about vulnerability description info if it is present
        if "title" in dependency_track_finding["vulnerability"] and dependency_track_finding["vulnerability"]["title"] is not None:
            vulnerability_description += "\nVulnerability Title: {title}".format(title=dependency_track_finding["vulnerability"]["title"])
        if "subtitle" in dependency_track_finding["vulnerability"] and dependency_track_finding["vulnerability"]["subtitle"] is not None:
            vulnerability_description += "\nVulnerability Subtitle: {subtitle}".format(subtitle=dependency_track_finding["vulnerability"]["subtitle"])
        if "description" in dependency_track_finding["vulnerability"] and dependency_track_finding["vulnerability"]["description"] is not None:
            vulnerability_description += "\nVulnerability Description: {description}".format(description=dependency_track_finding["vulnerability"]["description"])
        vuln_id_from_tool = None
        unique_id_from_tool = dependency_track_finding.get("matrix")
        if "uuid" in dependency_track_finding["vulnerability"] and dependency_track_finding["vulnerability"]["uuid"] is not None:
            vuln_id_from_tool = dependency_track_finding["vulnerability"]["uuid"]
        if "matrix" in dependency_track_finding["vulnerability"] and dependency_track_finding["vulnerability"]["matrix"] is not None:
            unique_id_from_tool = dependency_track_finding["vulnerability"]["matrix"]

        # Get severity according to Dependency Track and convert it to a severity DefectDojo understands
        dependency_track_severity = dependency_track_finding["vulnerability"]["severity"]
        vulnerability_severity = self._convert_dependency_track_severity_to_dojo_severity(dependency_track_severity)
        if vulnerability_severity is None:
            logger.warning("Detected severity of %s that could not be mapped for %s. Defaulting to Informational!", dependency_track_severity, title)
            vulnerability_severity = "Informational"

        # Get the cvss score of the vulnerabililty
        cvss_score = dependency_track_finding["vulnerability"].get("cvssV3BaseScore")

        cvssv3 = None
        if "cvssV3Vector" in dependency_track_finding["vulnerability"]:
            cvss_vector = dependency_track_finding["vulnerability"]["cvssV3Vector"]
            cvss_data = parse_cvss_data(cvss_vector)
            if cvss_data:
                cvssv3 = cvss_data.get("cvssv3")
                cvss_score = cvss_data.get("cvssv3_score")

        cvssv4 = None
        cvssv4_score = None
        if "cvssV4Vector" in dependency_track_finding["vulnerability"]:
            cvss_vector = dependency_track_finding["vulnerability"]["cvssV4Vector"]
            cvss_data = parse_cvss_data(cvss_vector)
            if cvss_data:
                cvssv4 = cvss_data.get("cvssv4")
                cvssv4_score = cvss_data.get("cvssv4_score")

        # Use the analysis state from Dependency Track to determine if the finding has already been marked as a false positive upstream
        analysis = dependency_track_finding.get("analysis")
        is_false_positive = bool(analysis is not None and analysis.get("state") == "FALSE_POSITIVE")

        if analysis is not None and analysis.get("detail"):
            vulnerability_description += f"\nAudit Detail: {analysis['detail']}"

        # Get the EPSS details
        epss_percentile = dependency_track_finding["vulnerability"].get("epssPercentile", None)

        epss_score = dependency_track_finding["vulnerability"].get("epssScore", None)

        references = dependency_track_finding["vulnerability"].get("references")
        if references:
            if isinstance(references, list):
                references = "\n".join(references)

        published = dependency_track_finding["vulnerability"].get("published")

        # Build and return Finding model
        finding = Finding(
            title=title,
            test=test,
            cwe=cwe,
            description=vulnerability_description,
            mitigation=self._derive_mitigation_from_affected_versions(dependency_track_finding),
            severity=vulnerability_severity,
            false_p=is_false_positive,
            component_name=component_name,
            component_version=component_version,
            file_path=file_path,
            unique_id_from_tool=unique_id_from_tool,
            vuln_id_from_tool=vuln_id_from_tool,
            references=references,
            static_finding=True,
            dynamic_finding=False)

        if is_false_positive:
            finding.is_mitigated = True
            finding.active = False

        if vulnerability_id:
            finding.unsaved_vulnerability_ids = vulnerability_id

        if cvss_score:
            finding.cvssv3_score = cvss_score
        if cvssv3:
            finding.cvssv3 = cvssv3

        if cvssv4_score:
            finding.cvssv4_score = cvssv4_score
        if cvssv4:
            finding.cvssv4 = cvssv4

        if published:
            finding.publish_date = parser.parse(published).date()

        if epss_score:
            finding.epss_score = epss_score
        if epss_percentile:
            finding.epss_percentile = epss_percentile

        if locations_enabled():
            if component_purl := dependency_track_finding.get("component", {}).get("purl"):
                finding.unsaved_locations.append(
                    LocationData.dependency(purl=component_purl),
                )

        return finding

    def get_scan_types(self):
        return ["Dependency Track Finding Packaging Format (FPF) Export"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "The Finding Packaging Format (FPF) from OWASP Dependency Track can be imported in JSON format. See here for more info on this JSON format."

    def get_findings(self, file, test):

        # Exit if file is not provided
        if file is None:
            return []

        # Load the contents of the JSON file into a dictionary
        data = file.read()
        try:
            findings_export_dict = json.loads(str(data, "utf-8"))
        except:
            findings_export_dict = json.loads(data)

        # Exit if file is an empty JSON dictionary
        if len(findings_export_dict.keys()) == 0:
            return []

        # Make sure the findings key exists in the dictionary and that it is not null or an empty list
        # If it is null or an empty list then exit
        if "findings" not in findings_export_dict or not findings_export_dict["findings"]:
            return []

        # Start with an empty list of findings
        items = []

        # If we have gotten this far then there should be one or more findings
        # Loop through each finding from Dependency Track
        for dependency_track_finding in findings_export_dict["findings"]:
            # Convert a Dependency Track finding to a DefectDojo finding
            dojo_finding = self._convert_dependency_track_finding_to_dojo_finding(dependency_track_finding, test)

            # Append DefectDojo finding to list
            items.append(dojo_finding)
        return items
