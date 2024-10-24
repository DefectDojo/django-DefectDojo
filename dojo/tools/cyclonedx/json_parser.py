import json
import logging

import dateutil

from dojo.models import Finding
from dojo.tools.cyclonedx.helpers import Cyclonedxhelper

LOGGER = logging.getLogger(__name__)


class CycloneDXJSONParser:
    def _get_findings_json(self, file, test):
        """Load a CycloneDX file in JSON format"""
        data = json.load(file)
        # Parse timestamp to get the report date
        report_date = None
        if data.get("metadata") and data.get("metadata").get("timestamp"):
            report_date = dateutil.parser.parse(
                data.get("metadata").get("timestamp"),
            )
        # for each component we keep data
        components = {}
        self._flatten_components(data.get("components", []), components)
        # for each vulnerabilities create one finding by component affected
        findings = []
        for vulnerability in data.get("vulnerabilities", []):
            description = vulnerability.get("description")
            detail = vulnerability.get("detail")
            if detail:
                if description:
                    description += f"\n{detail}"
                else:
                    description = f"\n{detail}"
            # if we have ratings we keep the first one
            # better than always 'Medium'
            ratings = vulnerability.get("ratings")
            if ratings:
                severity = ratings[0]["severity"]
                severity = Cyclonedxhelper().fix_severity(severity)
            else:
                severity = "Medium"
            references = ""
            advisories = vulnerability.get("advisories", [])
            for advisory in advisories:
                title = advisory.get("title")
                if title:
                    references += f"**Title:** {title}\n"
                url = advisory.get("url")
                if url:
                    references += f"**URL:** {url}\n"
                references += "\n"
            # for each component affected we create a finding if the "affects"
            # node is here
            for affect in vulnerability.get("affects", []):
                reference = affect["ref"]  # required by the specification
                component_name, component_version = Cyclonedxhelper()._get_component(
                    components, reference,
                )
                if not description:
                    description = "Description was not provided."
                finding = Finding(
                    title=f"{component_name}:{component_version} | {vulnerability.get('id')}",
                    test=test,
                    description=description,
                    severity=severity,
                    mitigation=vulnerability.get("recommendation", ""),
                    component_name=component_name,
                    component_version=component_version,
                    references=references,
                    static_finding=True,
                    dynamic_finding=False,
                    vuln_id_from_tool=vulnerability.get("id"),
                )
                if report_date:
                    finding.date = report_date
                ratings = vulnerability.get("ratings", [])
                for rating in ratings:
                    if (
                        rating.get("method") == "CVSSv3"
                        or rating.get("method") == "CVSSv31"
                    ):
                        raw_vector = rating["vector"]
                        cvssv3 = Cyclonedxhelper()._get_cvssv3(raw_vector)
                        severity = rating.get("severity")
                        if cvssv3:
                            finding.cvssv3 = cvssv3.clean_vector()
                            if severity:
                                finding.severity = Cyclonedxhelper().fix_severity(severity)
                            else:
                                finding.severity = cvssv3.severities()[0]
                vulnerability_ids = []
                # set id as first vulnerability id
                if vulnerability.get("id"):
                    vulnerability_ids.append(vulnerability.get("id"))
                # check references to see if we have other vulnerability ids
                for reference in vulnerability.get("references", []):
                    vulnerability_id = reference.get("id")
                    if vulnerability_id:
                        vulnerability_ids.append(vulnerability_id)
                if vulnerability_ids:
                    finding.unsaved_vulnerability_ids = vulnerability_ids
                # if there is some CWE
                cwes = vulnerability.get("cwes")
                if cwes and len(cwes) > 1:
                    # TODO: support more than one CWE
                    LOGGER.debug(
                        f"more than one CWE for a finding {cwes}. NOT supported by parser API",
                    )
                if cwes and len(cwes) > 0:
                    finding.cwe = cwes[0]
                # Check for mitigation
                analysis = vulnerability.get("analysis")
                if analysis:
                    state = analysis.get("state")
                    if state:
                        if (
                            state == "resolved"
                            or state == "resolved_with_pedigree"
                            or state == "not_affected"
                        ):
                            finding.is_mitigated = True
                            finding.active = False
                        elif state == "false_positive":
                            finding.false_p = True
                            finding.active = False
                        if not finding.active:
                            detail = analysis.get("detail")
                            if detail:
                                finding.mitigation = (
                                    finding.mitigation
                                    + f"\n**This vulnerability is mitigated and/or suppressed:** {detail}\n"
                                )
                findings.append(finding)
        return findings

    def _flatten_components(self, components, flatted_components):
        for component in components:
            if "components" in component:
                self._flatten_components(
                    component.get("components", []), flatted_components,
                )
            # according to specification 1.4, 'bom-ref' is mandatory but some
            # tools don't provide it
            if "bom-ref" in component:
                flatted_components[component["bom-ref"]] = component
        return
