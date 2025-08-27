import csv
import io
import re

from dateutil.parser import parse

from dojo.models import Endpoint, Finding
from dojo.tools.openvas.common import OpenVASFindingAuxData, deduplicate, is_valid_severity, update_description


def evaluate_bool_value(column_value):
    value = column_value.lower()
    if value == "true":
        return True
    if value == "false":
        return False
    return None


class OpenVASCSVParserV2:
    def get_findings(self, filename, test):
        dupes = {}
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")

        csv_reader = csv.reader(io.StringIO(content), delimiter=",", quotechar='"')
        column_names = [column_name.lower() for column_name in next(csv_reader) if column_name]

        for row in csv_reader:
            finding = Finding(test=test, dynamic_finding=True, static_finding=False, severity="Info")
            finding.unsaved_vulnerability_ids = []
            finding.unsaved_endpoints = [Endpoint()]
            aux_info = OpenVASFindingAuxData()

            for value, name in zip(row, column_names, strict=False):
                self.process_column_element(value, name, finding, aux_info)

            update_description(finding, aux_info)
            deduplicate(dupes, finding)

        return list(dupes.values())

    def process_column_element(
        self,
        column_value: str,
        column_name: str,
        finding: Finding,
        aux_info: OpenVASFindingAuxData,
    ):
        # skip columns with empty values
        if not column_value:
            return

        # process column names
        if column_name == "nvt name":
            finding.title = column_value
        elif column_name == "cweid":
            if column_value.isdigit():
                finding.cwe = int(column_value)
        elif column_name == "cves":
            for cve in column_value.split(","):
                finding.unsaved_vulnerability_ids.append(cve)
        elif column_name == "nvt oid":
            cve_pattern = r"CVE-\d{4}-\d{4,7}"  # legacy import
            cves = re.findall(cve_pattern, column_value)
            for cve in cves:
                finding.unsaved_vulnerability_ids.append(cve)
            if len(cves) == 0:
                finding.script_id = column_value
        elif column_name == "hostname":
            # strip due to https://github.com/greenbone/gvmd/issues/2378
            finding.unsaved_endpoints[0].host = column_value.strip()
        elif column_name == "ip":
            # fallback to ip if hostname is not aviable
            if not finding.unsaved_endpoints[0].host:
                # strip due to https://github.com/greenbone/gvmd/issues/2378
                finding.unsaved_endpoints[0].host = column_value.strip()
        elif column_name == "port":
            if column_value.isdigit():
                finding.unsaved_endpoints[0].port = int(column_value)
        elif column_name == "port protocol":
            finding.unsaved_endpoints[0].protocol = column_value
        elif column_name == "severity":
            if is_valid_severity(column_value):
                finding.severity = column_value
        elif column_name == "cvss":
            finding.cvssv3_score = float(column_value)
        elif column_name == "summary":
            finding.description = column_value
        elif column_name == "solution":
            finding.mitigation = column_value
        elif column_name == "vulnerability insight":
            finding.impact = column_value
        elif column_name == "specific result":
            finding.references = column_value
        elif column_name == "qod":
            aux_info.qod = column_value
        # columns not part of default openvas csv export
        elif column_name == "active":
            finding.active = evaluate_bool_value(column_value)
        elif column_name == "verified":
            finding.verified = evaluate_bool_value(column_value)
        elif column_name == "falsepositive":
            finding.false_p = evaluate_bool_value(column_value)
        elif column_name == "duplicate":
            finding.duplicate = evaluate_bool_value(column_value)
        elif column_name == "timestamp":
            finding.date = parse(column_value).date()
