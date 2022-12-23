import json
import logging
import re

import dateutil
from cvss import CVSS3
from defusedxml import ElementTree
from dojo.models import Finding

LOGGER = logging.getLogger(__name__)


class CycloneDXParser(object):
    """CycloneDX is a lightweight software bill of materials (SBOM) standard designed for use in application security contexts and supply chain component analysis.
    https://www.cyclonedx.org/
    """

    def get_scan_types(self):
        return ["CycloneDX Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "CycloneDX Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Support CycloneDX XML and JSON report formats (compatible with 1.4)."

    def _get_findings_xml(self, file, test):
        nscan = ElementTree.parse(file)
        root = nscan.getroot()
        namespace = self.get_namespace(root)
        if not namespace.startswith("{http://cyclonedx.org/schema/bom/"):
            raise ValueError(f"This doesn't seem to be a valid CycloneDX BOM XML file. Namespace={namespace}")
        ns = {
            "b": namespace.replace("{", "").replace("}", ""),  # we accept whatever the version
            "v": "http://cyclonedx.org/schema/ext/vulnerability/1.0",
        }
        # get report date
        report_date = None
        report_date_raw = root.findtext("b:metadata/b:timestamp", namespaces=ns)
        if report_date_raw:
            report_date = dateutil.parser.parse(report_date_raw)
        bom_refs = {}
        findings = []
        for component in root.findall("b:components/b:component", namespaces=ns):
            component_name = component.findtext(f"{namespace}name")
            component_version = component.findtext(f"{namespace}version")
            # save a ref
            if "bom-ref" in component.attrib:
                bom_refs[component.attrib["bom-ref"]] = {
                    "name": component_name,
                    "version": component_version,
                }
            # for each vulnerabilities add a finding
            for vulnerability in component.findall("v:vulnerabilities/v:vulnerability", namespaces=ns):
                finding_vuln = self.manage_vulnerability_legacy(
                    vulnerability,
                    ns,
                    bom_refs,
                    report_date=report_date,
                    component_name=component_name,
                    component_version=component_version,
                )
                findings.append(finding_vuln)

        # manage adhoc vulnerabilities
        for vulnerability in root.findall("v:vulnerabilities/v:vulnerability", namespaces=ns):
            finding_vuln = self.manage_vulnerability_legacy(vulnerability, ns, bom_refs, report_date)
            findings.append(finding_vuln)

        # manage adhoc vulnerabilities (compatible with 1.4 of the spec)
        for vulnerability in root.findall("b:vulnerabilities/b:vulnerability", namespaces=ns):
            findings.extend(self._manage_vulnerability_xml(vulnerability, ns, bom_refs, report_date))

        return findings

    def internal_deduplicate(self, dupes, dupe_key, finding):
        if dupe_key in dupes:
            find = dupes[dupe_key]
            find.nb_occurences += 1
        else:
            dupes[dupe_key] = finding

    def get_cwes(self, node, prefix, namespaces):
        cwes = []
        for cwe in node.findall(prefix + ":cwes/" + prefix + ":cwe", namespaces):
            if cwe.text.isdigit():
                cwes.append(int(cwe.text))
        return cwes

    def _get_cvssv3(self, raw_vector):
        if raw_vector is None or "" == raw_vector:
            return None
        if not raw_vector.startswith("CVSS:3"):
            raw_vector = "CVSS:3.1/" + raw_vector
        try:
            return CVSS3(raw_vector)
        except:
            LOGGER.exception(f"error while parsing vector CVSS v3 {raw_vector}")
            return None

    def manage_vulnerability_legacy(
        self, vulnerability, ns, bom_refs, report_date, component_name=None, component_version=None
    ):
        ref = vulnerability.attrib["ref"]
        vuln_id = vulnerability.findtext("v:id", namespaces=ns)

        severity = vulnerability.findtext("v:ratings/v:rating/v:severity", namespaces=ns)
        description = vulnerability.findtext("v:description", namespaces=ns)
        # by the schema, only id and ref are mandatory, even the severity is optional
        if not description:
            description = "\n".join(
                [
                    f"**Ref:** {ref}",
                    f"**Id:** {vuln_id}",
                    f"**Severity:** {str(severity)}",
                ]
            )

        if component_name is None:
            bom = bom_refs[ref]
            component_name = bom["name"]
            component_version = bom["version"]

        severity = self.fix_severity(severity)
        references = ""
        for adv in vulnerability.findall("v:advisories/v:advisory", namespaces=ns):
            references += f"{adv.text}\n"
        finding = Finding(
            title=f"{component_name}:{component_version} | {vuln_id}",
            description=description,
            severity=severity,
            references=references,
            component_name=component_name,
            component_version=component_version,
            vuln_id_from_tool=vuln_id,
            nb_occurences=1,
        )
        if report_date:
            finding.date = report_date
        mitigation = ""
        for recommend in vulnerability.findall("v:recommendations/v:recommendation", namespaces=ns):
            mitigation += f"{recommend.text}\n"
        if mitigation != "":
            finding.mitigation = mitigation

        # manage CVSS
        for rating in vulnerability.findall("v:ratings/v:rating", namespaces=ns):
            if "CVSSv3" == rating.findtext("v:method", namespaces=ns):
                raw_vector = rating.findtext("v:vector", namespaces=ns)
                severity = rating.findtext("v:severity", namespaces=ns)
                cvssv3 = self._get_cvssv3(raw_vector)
                if cvssv3:
                    finding.cvssv3 = cvssv3.clean_vector()
                    if severity:
                        finding.severity = self.fix_severity(severity)
                    else:
                        finding.severity = cvssv3.severities()[0]

        # if there is some CWE
        cwes = self.get_cwes(vulnerability, "v", ns)
        if len(cwes) > 1:
            # FIXME support more than one CWE
            LOGGER.debug(f"more than one CWE for a finding {cwes}. NOT supported by parser API")
        if len(cwes) > 0:
            finding.cwe = cwes[0]

        vulnerability_ids = list()
        # set id as first vulnerability id
        if vuln_id:
            vulnerability_ids.append(vuln_id)
        if vulnerability_ids:
            finding.unsaved_vulnerability_ids = vulnerability_ids

        return finding

    def _manage_vulnerability_xml(
        self, vulnerability, ns, bom_refs, report_date, component_name=None, component_version=None
    ):
        vuln_id = vulnerability.findtext("b:id", namespaces=ns)

        description = vulnerability.findtext("b:description", namespaces=ns)
        detail = vulnerability.findtext("b:detail", namespaces=ns)
        if detail:
            if description:
                description += f'\n{detail}'
            else:
                description = f'\n{detail}'

        severity = vulnerability.findtext("b:ratings/b:rating/b:severity", namespaces=ns)
        severity = self.fix_severity(severity)

        references = ""
        for advisory in vulnerability.findall("b:advisories/b:advisory", namespaces=ns):
            title = advisory.findtext("b:title", namespaces=ns)
            if title:
                references += f'**Title:** {title}\n'
            url = advisory.findtext("b:url", namespaces=ns)
            if url:
                references += f'**URL:** {url}\n'
            references += '\n'

        vulnerability_ids = list()
        # set id as first vulnerability id
        if vuln_id:
            vulnerability_ids.append(vuln_id)
        # check references to see if we have other vulnerability ids
        for reference in vulnerability.findall("b:references/b:reference", namespaces=ns):
            vulnerability_id = reference.findtext("b:id", namespaces=ns)
            if vulnerability_id:
                vulnerability_ids.append(vulnerability_id)

        # for all component affected
        findings = []
        for target in vulnerability.findall("b:affects/b:target", namespaces=ns):
            ref = target.find("b:ref", namespaces=ns)
            component_name, component_version = self._get_component(bom_refs, ref.text)

            finding = Finding(
                title=f"{component_name}:{component_version} | {vuln_id}",
                description=description,
                severity=severity,
                mitigation=vulnerability.findtext("b:recommendation", namespaces=ns),
                references=references,
                component_name=component_name,
                component_version=component_version,
                static_finding=True,
                dynamic_finding=False,
                vuln_id_from_tool=vuln_id,
                nb_occurences=1,
            )

            if vulnerability_ids:
                finding.unsaved_vulnerability_ids = vulnerability_ids

            if report_date:
                finding.date = report_date

            # manage CVSS
            for rating in vulnerability.findall("b:ratings/b:rating", namespaces=ns):
                method = rating.findtext("b:method", namespaces=ns)
                if "CVSSv3" == method or "CVSSv31" == method:
                    raw_vector = rating.findtext("b:vector", namespaces=ns)
                    severity = rating.findtext("b:severity", namespaces=ns)
                    cvssv3 = self._get_cvssv3(raw_vector)
                    if cvssv3:
                        finding.cvssv3 = cvssv3.clean_vector()
                        if severity:
                            finding.severity = self.fix_severity(severity)
                        else:
                            finding.severity = cvssv3.severities()[0]

            # if there is some CWE. Check both for old namespace and for 1.4
            cwes = self.get_cwes(vulnerability, "v", ns)
            if not cwes:
                cwes = self.get_cwes(vulnerability, "b", ns)
            if len(cwes) > 1:
                # FIXME support more than one CWE
                LOGGER.debug(f"more than one CWE for a finding {cwes}. NOT supported by parser API")
            if len(cwes) > 0:
                finding.cwe = cwes[0]

            # Check for mitigation
            analysis = vulnerability.findall("b:analysis", namespaces=ns)
            if analysis and len(analysis) == 1:
                state = analysis[0].findtext("b:state", namespaces=ns)
                if state:
                    if "resolved" == state or "resolved_with_pedigree" == state or "not_affected" == state:
                        finding.is_mitigated = True
                        finding.active = False
                    elif "false_positive" == state:
                        finding.false_p = True
                        finding.active = False
                    if not finding.active:
                        detail = analysis[0].findtext("b:detail", namespaces=ns)
                        if detail:
                            finding.mitigation = \
                                finding.mitigation + '\n**This vulnerability is mitigated and/or suppressed:** {}\n'.format(detail)

            findings.append(finding)

        return findings

    def get_namespace(self, element):
        """Extract namespace present in XML file."""
        m = re.match(r"\{.*\}", element.tag)
        return m.group(0) if m else ""

    def get_findings(self, file, test):
        if file.name.strip().lower().endswith(".json"):
            return self._get_findings_json(file, test)
        else:
            return self._get_findings_xml(file, test)

    def _get_findings_json(self, file, test):
        """Load a CycloneDX file in JSON format"""
        data = json.load(file)

        # Parse timestamp to get the report date
        report_date = None
        if data.get("metadata") and data.get("metadata").get("timestamp"):
            report_date = dateutil.parser.parse(data.get("metadata").get("timestamp"))

        # for each component we keep data
        components = {}
        for component in data.get("components", []):
            # according to specification 1.4, 'bom-ref' is mandatory but some tools don't provide it
            if "bom-ref" in component:
                components[component["bom-ref"]] = component
        # for each vulnerabilities create one finding by component affected
        findings = []
        for vulnerability in data.get("vulnerabilities", []):
            description = vulnerability.get("description")
            detail = vulnerability.get("detail")
            if detail:
                if description:
                    description += f'\n{detail}'
                else:
                    description = f'\n{detail}'

            # if we have ratings we keep the first one
            # better than always 'Medium'
            ratings = vulnerability.get("ratings")
            if ratings:
                severity = ratings[0]["severity"]
                severity = self.fix_severity(severity)
            else:
                severity = "Medium"

            references = ""
            advisories = vulnerability.get('advisories', [])
            for advisory in advisories:
                title = advisory.get('title')
                if title:
                    references += f'**Title:** {title}\n'
                url = advisory.get('url')
                if url:
                    references += f'**URL:** {url}\n'
                references += '\n'

            # for each component affected we create a finding if the "affects" node is here
            for affect in vulnerability.get("affects", []):
                reference = affect["ref"]  # required by the specification
                component_name, component_version = self._get_component(components, reference)
                finding = Finding(
                    title=f"{component_name}:{component_version} | {vulnerability.get('id')}",
                    test=test,
                    description=description,
                    severity=severity,
                    mitigation=vulnerability.get("recommendation"),
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
                    if rating.get("method") == "CVSSv3" or rating.get("method") == "CVSSv31":
                        raw_vector = rating["vector"]
                        cvssv3 = self._get_cvssv3(raw_vector)
                        severity = rating.get("severity")
                        if cvssv3:
                            finding.cvssv3 = cvssv3.clean_vector()
                            if severity:
                                finding.severity = self.fix_severity(severity)
                            else:
                                finding.severity = cvssv3.severities()[0]

                vulnerability_ids = list()
                # set id as first vulnerability id
                if vulnerability.get('id'):
                    vulnerability_ids.append(vulnerability.get('id'))
                # check references to see if we have other vulnerability ids
                for reference in vulnerability.get("references", []):
                    vulnerability_id = reference.get("id")
                    if vulnerability_id:
                        vulnerability_ids.append(vulnerability_id)
                if vulnerability_ids:
                    finding.unsaved_vulnerability_ids = vulnerability_ids

                # if there is some CWE
                cwes = vulnerability.get('cwes')
                if cwes and len(cwes) > 1:
                    # FIXME support more than one CWE
                    LOGGER.debug(f"more than one CWE for a finding {cwes}. NOT supported by parser API")
                if cwes and len(cwes) > 0:
                    finding.cwe = cwes[0]

                # Check for mitigation
                analysis = vulnerability.get('analysis')
                if analysis:
                    state = analysis.get('state')
                    if state:
                        if "resolved" == state or "resolved_with_pedigree" == state or "not_affected" == state:
                            finding.is_mitigated = True
                            finding.active = False
                        elif "false_positive" == state:
                            finding.false_p = True
                            finding.active = False
                        if not finding.active:
                            detail = analysis.get("detail")
                            if detail:
                                finding.mitigation = \
                                    finding.mitigation + '\n**This vulnerability is mitigated and/or suppressed:** {}\n'.format(detail)

                findings.append(finding)
        return findings

    def _get_component(self, components, reference):
        if reference not in components:
            LOGGER.warning(f"reference:{reference} not found in the BOM")
            return (None, None)
        if "version" not in components[reference]:
            return (components[reference]["name"], None)
        return (components[reference]["name"], components[reference]["version"])

    def fix_severity(self, severity):
        severity = severity.capitalize()
        if severity is None:
            severity = "Medium"
        elif "Unknown" == severity or "None" == severity:
            severity = "Info"
        return severity
