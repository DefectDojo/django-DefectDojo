import contextlib
from xml.dom import NamespaceErr

from defusedxml import ElementTree

from dojo.models import Endpoint, Finding
from dojo.tools.openvas.common import OpenVASFindingAuxData, deduplicate, is_valid_severity, update_description


class OpenVASXMLParser:
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

            update_description(finding, aux_info)
            deduplicate(dupes, finding)

        return list(dupes.values())

    def process_field_element(self, field, finding: Finding, aux_info: OpenVASFindingAuxData):
        if not field.text:
            return

        if field.tag == "name":
            finding.title = field.text
        elif field.tag == "nvt":
            finding.script_id = field.get("oid")
            nvt_name = field.find("name").text
            if nvt_name:
                finding.title = nvt_name
        elif field.tag == "hostname":
            # strip due to https://github.com/greenbone/gvmd/issues/2378
            finding.unsaved_endpoints[0].host = field.text.strip()
        elif field.tag == "host":
            if not finding.unsaved_endpoints[0].host:
                # strip due to https://github.com/greenbone/gvmd/issues/2378
                finding.unsaved_endpoints[0].host = field.text.strip()
        elif field.tag == "port":
            port_str, protocol = field.text.split("/")
            with contextlib.suppress(ValueError):
                finding.unsaved_endpoints[0].port = int(port_str)
            finding.unsaved_endpoints[0].protocol = protocol
        elif field.tag == "severity":
            finding.cvssv3_score = float(field.text)
        elif field.tag == "threat":
            if is_valid_severity(field.text):
                finding.severity = field.text
        elif field.tag == "qod":
            aux_info.qod = field.text
        elif field.tag == "description":
            finding.description = field.text
