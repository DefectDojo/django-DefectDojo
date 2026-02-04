import contextlib
import logging
from xml.dom import NamespaceErr

from defusedxml import ElementTree

from dojo.models import Finding
from dojo.tools.openvas.parser_v2.common import (
    OpenVASFindingAuxData,
    cleanup_openvas_text,
    deduplicate,
    get_location,
    is_valid_severity,
    postprocess_finding,
    setup_finding,
)
from dojo.utils import parse_cvss_data

logger = logging.getLogger(__name__)


def get_findings_from_xml(file, test) -> list[Finding]:
    """Returns list of findings as defectdojo factory contract expects"""
    dupes = {}
    tree = ElementTree.parse(file)
    root = tree.getroot()

    if "report" not in root.tag:
        msg = "This doesn't seem to be a valid Greenbone/ OpenVAS XML file."
        raise NamespaceErr(msg)

    report = root.find("report")
    results = report.find("results")

    parser = XMLParserV2()
    for result in results:
        finding, aux_info = setup_finding(test)
        for element in result:
            parser.process_element(element, finding, aux_info)

        postprocess_finding(finding, aux_info)
        deduplicate(dupes, finding)

    return list(dupes.values())


class XMLParserV2:
    def __init__(self):
        self.tag_handlers = {
            "nvt": self._handle_nvt,
            "qod": self._handle_qod,
            "name": self._handle_name,
            "host": self._handle_host,
            "port": self._handle_port,
            "severity": self._handle_severity,
            "threat": self._handle_threat,
            "description": self._handle_description,
        }

    def process_element(self, field, finding: Finding, aux_info: OpenVASFindingAuxData):
        # tmp save common values in object for cleaner method signature
        self.finding = finding
        self.aux_info = aux_info

        handler = self.tag_handlers.get(field.tag)
        try:
            if handler:
                handler(field)
        except ValueError as e:
            logger.debug("openvas parser v2: error parsing field %s: %s", field.tag, e)

    def _handle_nvt(self, field):
        self.finding.vuln_id_from_tool = field.get("oid")
        nvt_name = field.find("name").text
        if nvt_name:
            self.finding.title = nvt_name

        # parse solution (also included in tags field if backup is needed)
        solution = field.find("solution")
        if solution is not None:
            self.finding.mitigation = cleanup_openvas_text(solution.text)

        # parse cves and references
        refs_node = field.find("refs")
        if refs_node is not None:
            # this field can contain cves, other security vendors ids or urls
            refs = refs_node.findall(".//ref")
            self.finding.unsaved_vulnerability_ids = [ref.get("id") for ref in refs if ref.get("type") == "cve"]
            # only include urls in references
            self.aux_info.references = [ref.get("id") for ref in refs if ref.get("type") != "cve"]

        # parse tags fields
        tag_field = field.find("tags")
        tags = self._parse_nvt_tags(tag_field.text)
        summary = tags.get("summary", None)
        if summary:
            self.aux_info.summary = summary

        impact = tags.get("impact", None)
        if impact:
            self.finding.impact = cleanup_openvas_text(impact)

        cvss_base_vector = tags.get("cvss_base_vector", None)
        if cvss_base_vector:
            cvss_data = parse_cvss_data(cvss_base_vector)
            self.finding.cvssv3 = cvss_data["cvssv3"]
            self.finding.cvssv4 = cvss_data["cvssv4"]

            # only report the score as cvssv3 if cvss major version is 2
            # as cvss v2 vectors are not supported
            if cvss_data["major_version"] == 2:
                self.finding.cvssv3_score = cvss_data["cvssv2_score"]

    def _handle_qod(self, field):
        self.aux_info.qod = field.find("value").text

    def _handle_name(self, field):
        if field.text:
            self.finding.title = field.text

    def _handle_host(self, field):
        if field.text:
            hostname_field = field.find("hostname")
            # default to hostname else ip
            if hostname_field is not None and hostname_field.text:
                # strip due to https://github.com/greenbone/gvmd/issues/2378
                get_location(self.finding).host = hostname_field.text.strip()
            else:
                # strip due to https://github.com/greenbone/gvmd/issues/2378
                get_location(self.finding).host = field.text.strip()

    def _handle_port(self, field):
        if field.text:
            port_str, protocol = field.text.split("/")
            get_location(self.finding).protocol = protocol
            with contextlib.suppress(ValueError):
                get_location(self.finding).port = int(port_str)

    def _handle_severity(self, field):
        if field.text:
            self.aux_info.fallback_cvss_score = float(field.text)

    def _handle_threat(self, field):
        if field.text and is_valid_severity(field.text):
            self.finding.severity = field.text

    def _handle_description(self, field):
        if field.text:
            self.aux_info.openvas_result = field.text.strip()

    def _parse_nvt_tags(self, text: str) -> dict[str, str]:
        """
        Parse tags in nvt field into dict
        Example:

            Input: "summary=This is a test|impact=High|solution=Update software"
            Output: {"summary": "This is a test", "impact": "High", "solution": "Update software"}
        """
        parts = text.strip().split("|")
        tags = {}

        for part in parts:
            idx = part.find("=")
            if idx == -1 or (len(part) < idx + 2):
                continue

            key = part[0:idx]
            val = part[idx + 1 :]
            tags[key] = val
        return tags
