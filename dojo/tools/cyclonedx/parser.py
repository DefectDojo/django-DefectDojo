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
        return ["cyclonedx"]

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
            "v": "http://cyclonedx.org/schema/ext/vulnerability/1.0",
        }
        # get report date
        report_date = None
        report_date_raw = root.findtext(f"{namespace}metadata/{namespace}timestamp")
        if report_date_raw:
            report_date = dateutil.parser.parse(report_date_raw)
        bom_refs = {}
        dupes = {}
        for component in root.findall(f"{namespace}components/{namespace}component"):
            print('comp')
            component_name = component.findtext(f"{namespace}name")
            component_version = component.findtext(f"{namespace}version")
            # add finding for the component
            self.manage_component(dupes, component, report_date, namespace)
            # save a ref
            if "bom-ref" in component.attrib:
                bom_refs[component.attrib["bom-ref"]] = {
                    "name": component_name,
                    "version": component_version,
                }
            for vulnerability in component.findall(
                "v:vulnerabilities/v:vulnerability", namespaces=ns
            ):
                self.manage_vulnerability(
                    dupes,
                    vulnerability, namespace,
                    bom_refs,
                    report_date=report_date,
                    component_name=component_name,
                    component_version=component_version,
                )
        # manage adhoc vulnerabilities
        for vulnerability in root.findall(
            "v:vulnerabilities/v:vulnerability", namespaces=ns
        ):
            self.manage_vulnerability(dupes, vulnerability, namespace, bom_refs, report_date)

        return list(dupes.values())

    def get_cwes(self, node, namespaces):
        cwes = []
        for cwe in node.findall("v:cwes/v:cwe", namespaces):
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
                    return CVSS3(raw_vector)
                except:
                    LOGGER.exception(f"error while parsing vector CVSS v3 {raw_vector}")
                    return None
        return None

    def manage_vulnerability(
        self, dupes, vulnerability, namespace, bom_refs, report_date, component_name=None, component_version=None
    ):
        ns = {
            "v": "http://cyclonedx.org/schema/ext/vulnerability/1.0",
        }
        ref = vulnerability.attrib["ref"]
        cve = vulnerability.findtext("v:id", namespaces=ns)

        title = cve
        severity = vulnerability.findtext(
            "v:ratings/v:rating/v:severity", namespaces=ns
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
        for adv in vulnerability.findall("v:advisories/v:advisory", namespaces=ns):
            references += f"{adv.text}\n"

        dupe_key = "vulnerability" + ref

        if dupe_key in dupes:
            find = dupes[dupe_key]
            find.description += description
            find.nb_occurences += 1
        else:
            find = Finding(
                title=title,
                description=description,
                severity=severity,
                numerical_severity=Finding.get_numerical_severity(severity),
                references=references,
                cve=cve,
                component_name=component_name,
                component_version=component_version,
                unique_id_from_tool=cve,
                nb_occurences=1,
            )
            if report_date:
                find.date = report_date
            # manage CVSS
            cvssv3 = self._get_cvssv3(vulnerability)
            if cvssv3:
                cvssv3.compute_base_score()
                find.cvssv3 = cvssv3.clean_vector()
                find.cvssv3_score = float(cvssv3.base_score)
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
            dupe_key = bom_ref
        else:
            dupe_key = hashlib.sha256("|".join(
                [
                    "component",
                    component_name,
                    component_version,
                ]
            ).encode("utf-8")).hexdigest()

        if dupe_key in dupes:
            find = dupes[dupe_key]
            find.description += description
            find.nb_occurences += 1
        else:
            find = Finding(
                title=f'Component detected {component_name}:{component_version}',
                description=description,
                severity="Info",
                numerical_severity=Finding.get_numerical_severity("Info"),
                component_name=component_name,
                component_version=component_version,
                nb_occurences=1,
            )
            if report_date:
                find.date = report_date

            dupes[dupe_key] = find

    def get_namespace(self, element):
        """Extract namespace present in XML file."""
        m = re.match(r'\{.*\}', element.tag)
        return m.group(0) if m else ''
