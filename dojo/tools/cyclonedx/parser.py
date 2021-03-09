import logging

from cvss import CVSS3
from defusedxml import ElementTree

from dojo.models import Finding

LOGGER = logging.getLogger(__name__)


class CycloneDXParser(object):
    """CycloneDX is a lightweight software bill of materials (SBOM) standard designed for use in application security contexts and supply chain component analysis.
    https://www.cyclonedx.org/
    """

    ns = {
        "v": "http://cyclonedx.org/schema/ext/vulnerability/1.0",
        "x": "http://cyclonedx.org/schema/bom/1.2",
    }

    def get_scan_types(self):
        return ["cyclonedx"]

    def get_label_for_scan_types(self, scan_type):
        return "CycloneDX Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Reports can be imported CycloneDX (XML) report formats."

    def get_findings(self, file, test):
        nscan = ElementTree.parse(file)
        root = nscan.getroot()
        bom_refs = {}
        dupes = {}
        for component in root.findall("x:components/x:component", namespaces=self.ns):
            component_name = component.findtext("x:name", namespaces=self.ns)
            component_version = component.findtext("x:version", namespaces=self.ns)
            # save a ref
            if "bom-ref" in component.attrib:
                bom_refs[component.attrib["bom-ref"]] = {
                    "name": component_name,
                    "version": component_version,
                }
            for vulnerability in component.findall(
                "v:vulnerabilities/v:vulnerability", namespaces=self.ns
            ):
                self.manage_vulnerability(
                    dupes,
                    vulnerability,
                    bom_refs,
                    component_name=component_name,
                    component_version=component_version,
                )
        # manage adhoc vulnerabilities
        for vulnerability in root.findall(
            "v:vulnerabilities/v:vulnerability", namespaces=self.ns
        ):
            self.manage_vulnerability(dupes, vulnerability, bom_refs)

        return list(dupes.values())

    def get_cwes(self, node):
        cwes = []
        for cwe in node.findall("v:cwes/v:cwe", namespaces=self.ns):
            if cwe.text.isdigit():
                cwes.append(int(cwe.text))
        return cwes

    def _get_cvssv3(self, node):
        for rating in node.findall("v:ratings/v:rating", namespaces=self.ns):
            if "CVSSv3" == rating.findtext("v:method", namespaces=self.ns):
                raw_vector = rating.findtext("v:vector", namespaces=self.ns)
                if raw_vector is None or "" == raw_vector:
                    return None
                if not raw_vector.startswith("CVSS:3"):
                    raw_vector = "CVSS:3.1/" + raw_vector
                try:
                    return CVSS3(raw_vector).clean_vector(output_prefix=False)
                except:
                    LOGGER.exception(f"error while parsing vector CVSS v3 {raw_vector}")
                    return None
        return None

    def manage_vulnerability(
        self, dupes, vulnerability, bom_refs, component_name=None, component_version=None
    ):
        ref = vulnerability.attrib["ref"]
        cve = vulnerability.findtext("v:id", namespaces=self.ns)

        title = cve
        severity = vulnerability.findtext(
            "v:ratings/v:rating/v:severity", namespaces=self.ns
        )
        description = "\n".join(
            [
                f"**Ref:** {ref}",
                f"**Id:** {cve}",
                f"**Severity:** {severity}",
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
        for adv in vulnerability.findall("v:advisories/v:advisory", namespaces=self.ns):
            references += f"{adv.text}\n"
        impact = "No impact provided"
        mitigation = "No mitigation provided"

        dupe_key = ref

        if dupe_key in dupes:
            find = dupes[dupe_key]
            find.description += description
            find.nb_occurences += 1
        else:
            find = Finding(
                title=title,
                active=False,
                verified=False,
                description=description,
                severity=severity,
                mitigation=mitigation,
                impact=impact,
                references=references,
                cve=cve,
                cvssv3=self._get_cvssv3(vulnerability),
                component_name=component_name,
                component_version=component_version,
                unique_id_from_tool=ref,
                nb_occurences=1,
            )
            # if there is some CWE
            cwes = self.get_cwes(vulnerability)
            if len(cwes) > 1:
                # FIXME support more than one CWE
                LOGGER.warning(
                    f"more than one CWE for a finding {cwes}. NOT supported by parser API"
                )
            if len(cwes) > 0:
                find.cwe = cwes[0]
            dupes[dupe_key] = find
