import contextlib
from xml.dom import NamespaceErr

from defusedxml import ElementTree

from dojo.models import Endpoint, Finding
from dojo.tools.openvas_v2.common import (
    OpenVASFindingAuxData,
    cleanup_openvas_text,
    deduplicate,
    is_valid_severity,
    update_finding,
)


class OpenVASXMLParserV2:
    def get_findings(self, filename, test):
        dupes = {}
        tree = ElementTree.parse(filename)
        root = tree.getroot()

        if "report" not in root.tag:
            msg = "This doesn't seem to be a valid Greenbone/ OpenVAS XML file."
            raise NamespaceErr(msg)

        report = root.find("report")
        results = report.find("results")

        for result in results:
            finding = Finding(
                test=test,
                dynamic_finding=True,
                static_finding=False,
                severity="Info",
            )
            aux_info = OpenVASFindingAuxData()

            finding.unsaved_vulnerability_ids = []
            finding.unsaved_endpoints = [Endpoint()]

            for field in result:
                self.process_field_element(field, finding, aux_info)

            update_finding(finding, aux_info)
            deduplicate(dupes, finding)

        return list(dupes.values())

    def parse_nvt_tags(self, text):
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

    def process_field_element(self, field, finding: Finding, aux_info: OpenVASFindingAuxData):
        if field.tag == "nvt":
            # parse general field
            finding.vuln_id_from_tool = field.get("oid")
            nvt_name = field.find("name").text
            if nvt_name:
                finding.title = nvt_name

            # parse tags field
            tag_field = field.find("tags")
            tags = self.parse_nvt_tags(tag_field.text)
            summary = tags.get("summary", None)
            if summary:
                aux_info.summary = summary

            impact = tags.get("impact", None)
            if impact:
                finding.impact = cleanup_openvas_text(impact)

            # parse cves
            refs_node = field.find("refs")
            if refs_node is not None:
                refs = refs_node.findall(".//ref[@type='cve']")
                finding.unsaved_vulnerability_ids = [ref.get("id") for ref in refs]
        elif field.tag == "qod":
            aux_info.qod = field.find("value").text

        if not field.text:
            return

        if field.tag == "name":
            finding.title = field.text
        elif field.tag == "host":
            hostname_field = field.find("hostname")
            # default to hostname else ip
            if hostname_field is not None and hostname_field.text:
                # strip due to https://github.com/greenbone/gvmd/issues/2378
                finding.unsaved_endpoints[0].host = hostname_field.text.strip()
            else:
                # strip due to https://github.com/greenbone/gvmd/issues/2378
                finding.unsaved_endpoints[0].host = field.text.strip()
        elif field.tag == "port":
            port_str, protocol = field.text.split("/")
            finding.unsaved_endpoints[0].protocol = protocol
            with contextlib.suppress(ValueError):
                finding.unsaved_endpoints[0].port = int(port_str)
        elif field.tag == "severity":
            finding.cvssv3_score = float(field.text)
        elif field.tag == "threat":
            if is_valid_severity(field.text):
                finding.severity = field.text
        elif field.tag == "description":
            aux_info.openvas_result = field.text.strip()
        elif field.tag == "solution":
            finding.mitigation = cleanup_openvas_text(field.text)
