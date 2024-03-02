import json
import logging

import dateutil
from cvss import CVSS3
from dojo.tools.cyclonedx.json_parser import CycloneDXJSONParser
from dojo.tools.cyclonedx.xml_parser import CycloneDXXMLParser
from dojo.models import Finding

LOGGER = logging.getLogger(__name__)


class CycloneDXParser(object):
    """CycloneDX is a lightweight software bill of materials (SBOM) standard designed for use in application security
    contexts and supply chain component analysis.
    https://www.cyclonedx.org/
    """

    def get_scan_types(self):
        return ["CycloneDX Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "CycloneDX Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Support CycloneDX XML and JSON report formats (compatible with 1.4)."



    def internal_deduplicate(self, dupes, dupe_key, finding):
        if dupe_key in dupes:
            find = dupes[dupe_key]
            find.nb_occurences += 1
        else:
            dupes[dupe_key] = finding


    def get_findings(self, file, test):
        if file.name.strip().lower().endswith(".json"):
            return CycloneDXJSONParser()._get_findings_json(file, test)
        else:
            return CycloneDXXMLParser()._get_findings_xml(file, test)



    def _flatten_components(self, components, flatted_components):
        for component in components:
            if "components" in component:
                self._flatten_components(
                    component.get("components", []), flatted_components
                )
            # according to specification 1.4, 'bom-ref' is mandatory but some
            # tools don't provide it
            if "bom-ref" in component:
                flatted_components[component["bom-ref"]] = component
        return None

    

    def fix_severity(self, severity):
        severity = severity.capitalize()
        if severity is None:
            severity = "Medium"
        elif "Unknown" == severity or "None" == severity:
            severity = "Info"
        return severity
