from dojo.tools.spdx.json_parser import SpdxJSONParser
from dojo.tools.spdx.tag_value_parser import SpdxTagValueParser


class SpdxParser:

    """
    SPDX (Software Package Data Exchange) is an ISO-standard software bill of materials format, and
    the format named in US federal SBOM procurement guidance.

    SPDX 2.x has no vulnerability container, so this parser behaves like the CycloneDX parser: the
    package list becomes component/dependency inventory recorded on the test, and findings are created
    only where the document carries an actual weakness signal - a SECURITY external reference of an
    advisory type naming a vulnerability identifier.

    https://spdx.dev/
    """

    def get_scan_types(self):
        return ["SPDX Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "SPDX Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Support SPDX 2.2 and 2.3 in JSON and tag-value format. Packages become component "
            "inventory; SECURITY external references naming a CVE or GHSA become findings. "
            "SPDX 3.0 (JSON-LD) is not supported yet."
        )

    def get_findings(self, file, test):
        if file.name.strip().lower().endswith(".json"):
            return SpdxJSONParser().get_findings(file, test)
        return SpdxTagValueParser().get_findings(file, test)
