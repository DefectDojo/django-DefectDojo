import logging
import hashlib
import re

from cvss import CVSS3
from defusedxml import ElementTree
import dateutil

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
        return "Reports can be imported CycloneDX (XML) report formats."

    def get_findings(self, file, test):
        nscan = ElementTree.parse(file)
        root = nscan.getroot()
        namespace = self.get_namespace(root)
        if not namespace.startswith('{http://cyclonedx.org/schema/bom/'):
            raise ValueError(f"This doesn't seem to be a valid CyclonDX BOM XML file. Namespace={namespace}")
        ns = {
            "b": namespace.replace('{', '').replace('}', ''),  # we accept whatever the version
            "v": "http://cyclonedx.org/schema/ext/vulnerability/1.0",
        }
        # get report date
        report_date = None
        report_date_raw = root.findtext("b:metadata/b:timestamp", namespaces=ns)
        if report_date_raw:
            report_date = dateutil.parser.parse(report_date_raw)
        bom_refs = {}
        dupes = {}
        for component in root.findall("b:components/b:component", namespaces=ns):
            component_name = component.findtext(f"{namespace}name")
            component_version = component.findtext(f"{namespace}version")
            # save a ref
            if "bom-ref" in component.attrib:
                bom_refs[component.attrib["bom-ref"]] = {
                    "name": component_name,
                    "version": component_version,
                }
            # add finding for the component
            key, finding = self.manage_component(dupes, component, report_date, namespace)
            self.internal_deduplicate(dupes, key, finding)
            # for each vulnerabilities add a finding
            for vulnerability in component.findall(
                "v:vulnerabilities/v:vulnerability", namespaces=ns
            ):
                key_vuln, finding_vuln = self.manage_vulnerability(
                    dupes,
                    vulnerability, ns,
                    bom_refs,
                    report_date=report_date,
                    component_name=component_name,
                    component_version=component_version,
                )
                self.internal_deduplicate(dupes, key_vuln, finding_vuln)
        # manage adhoc vulnerabilities
        for vulnerability in root.findall(
            "v:vulnerabilities/v:vulnerability", namespaces=ns
        ):
            key_vuln, finding_vuln = self.manage_vulnerability(dupes, vulnerability, ns, bom_refs, report_date)
            self.internal_deduplicate(dupes, key_vuln, finding_vuln)

        return list(dupes.values())

    def internal_deduplicate(self, dupes, dupe_key, finding):
        if dupe_key in dupes:
            find = dupes[dupe_key]
            find.description += "\n\n-----\n" + finding.description
            find.nb_occurences += 1
        else:
            dupes[dupe_key] = finding

    def get_cwes(self, node, namespaces):
        cwes = []
        for cwe in node.findall("v:cwes/v:cwe", namespaces):
            if cwe.text.isdigit():
                cwes.append(int(cwe.text))
        return cwes

    def _get_cvssv3(self, node, namespaces):
        for rating in node.findall("v:ratings/v:rating", namespaces=namespaces):
            if "CVSSv3" == rating.findtext("v:method", namespaces=namespaces):
                raw_vector = rating.findtext("v:vector", namespaces=namespaces)
                if raw_vector is None or "" == raw_vector:
                    return None
                if not raw_vector.startswith("CVSS:3"):
                    raw_vector = "CVSS:3.1/" + raw_vector
                try:
                    return CVSS3(raw_vector)
                except:
                    LOGGER.exception(f"error while parsing vector CVSS v3 {raw_vector}")
                    return None
        return None

    def manage_vulnerability(
        self, dupes, vulnerability, ns, bom_refs, report_date, component_name=None, component_version=None
    ):
        ref = vulnerability.attrib["ref"]
        vuln_id = vulnerability.findtext("v:id", namespaces=ns)

        severity = vulnerability.findtext(
            "v:ratings/v:rating/v:severity", namespaces=ns
        )
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

        if severity is None:
            severity = "Medium"
        if "Unknown" == severity:
            severity = "Info"
        if "None" == severity:
            severity = "Info"
        references = ""
        for adv in vulnerability.findall("v:advisories/v:advisory", namespaces=ns):
            references += f"{adv.text}\n"

        finding = Finding(
                title=vuln_id,
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

        # manage if the ID is a CVE
        if re.fullmatch("CVE-[0-9]+-[0-9]+", vuln_id):
            finding.cve = vuln_id

        # manage CVSS
        cvssv3 = self._get_cvssv3(vulnerability, ns)
        if cvssv3:
            finding.cvssv3 = cvssv3.clean_vector()

        # if there is some CWE
        cwes = self.get_cwes(vulnerability, ns)
        if len(cwes) > 1:
            # FIXME support more than one CWE
            LOGGER.warning(
                f"more than one CWE for a finding {cwes}. NOT supported by parser API"
            )
        if len(cwes) > 0:
            finding.cwe = cwes[0]

        dupe_key = hashlib.sha256("|".join(
            [
                "vulnerability",
                ref,
            ]
        ).encode("utf-8")).hexdigest()

        return dupe_key, finding

    def manage_component(self, dupes, component_node, report_date, namespace):
        bom_ref = component_node.attrib.get('bom-ref')
        component_name = component_node.findtext(f"{namespace}name")
        component_version = component_node.findtext(f"{namespace}version")
        description = "\n".join(
            [
                f"**Ref:** {bom_ref}",
                f"**Type:** {component_node.attrib.get('type')}",
                f"**Name:** {component_name}",
                f"**Version:** {component_version}",
            ]
        )

        if bom_ref:
            dupe_key = hashlib.sha256("|".join(
                [
                    "component",
                    bom_ref,
                ]
            ).encode("utf-8")).hexdigest()
        else:
            dupe_key = hashlib.sha256("|".join(
                [
                    "component",
                    component_name,
                    component_version,
                ]
            ).encode("utf-8")).hexdigest()

        finding = Finding(
            title=f'Component detected {component_name}:{component_version}',
            description=description,
            severity="Info",
            component_name=component_name,
            component_version=component_version,
            nb_occurences=1,
        )
        if report_date:
            finding.date = report_date

        return dupe_key, finding

    def get_namespace(self, element):
        """Extract namespace present in XML file."""
        m = re.match(r'\{.*\}', element.tag)
        return m.group(0) if m else ''
