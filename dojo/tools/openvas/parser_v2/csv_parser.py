import csv
import io
import logging

from dateutil.parser import parse as parse_date

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

logger = logging.getLogger(__name__)


def get_findings_from_csv(file, test) -> list[Finding]:
    """Returns list of findings as defectdojo factory contract expects"""
    dupes = {}
    if not isinstance(file, io.TextIOWrapper):
        file = io.TextIOWrapper(file, encoding="utf-8")
    csv_reader = csv.reader(file, delimiter=",", quotechar='"')
    column_names = [column_name.lower() for column_name in next(csv_reader) if column_name]

    if "nvt name" not in column_names:
        msg = "Invalid OpenVAS csv file"
        raise ValueError(msg)

    parser = CSVParserV2()
    for row in csv_reader:
        finding, aux_info = setup_finding(test)

        for column_value, column_name in zip(row, column_names, strict=False):
            parser.process_column(column_name, column_value, finding, aux_info)

        postprocess_finding(finding, aux_info)
        deduplicate(dupes, finding)

    return list(dupes.values())


class CSVParserV2:
    def __init__(self):
        self.column_handlers = {
            "nvt name": self._handle_nvt_name,
            "cweid": self._handle_cweid,
            "cves": self._handle_cves,
            "nvt oid": self._handle_nvt_oid,
            "hostname": self._handle_hostname,
            "ip": self._handle_ip,
            "port": self._handle_port,
            "port protocol": self._handle_port_protocol,
            "severity": self._handle_severity,
            "cvss": self._handle_cvss,
            "summary": self._handle_summary,
            "solution": self._handle_solution,
            "vulnerability insight": self._handle_vulnerability_insight,
            "specific result": self._handle_specific_result,
            "qod": self._handle_qod,
            "max severity epss score": self._handle_epss_score,
            "max severity epss percentile": self._handle_epss_percentile,
            "timestamp": self._handle_timestamp,
            "active": self._handle_active,
            "verified": self._handle_verified,
            "falsepositive": self._handle_falsepositive,
            "duplicate": self._handle_duplicate,
            "other references": self._handle_references,
        }

    def process_column(
        self,
        column_name: str,
        column_value: str,
        finding: Finding,
        aux_info: OpenVASFindingAuxData,
    ):
        # skip columns with empty values
        if not column_value:
            return

        # tmp save common values in object for cleaner method signature
        self.finding = finding
        self.aux_info = aux_info

        handler = self.column_handlers.get(column_name)
        try:
            if handler:
                handler(column_value)
        except ValueError as e:
            logger.debug("openvas parser v2: error parsing column %s: %s", column_name, e)

    def _handle_nvt_name(self, column_value: str):
        self.finding.title = column_value

    def _handle_cweid(self, column_value: str):
        if column_value.isdigit():
            self.finding.cwe = int(column_value)

    def _handle_cves(self, column_value: str):
        for cve in column_value.split(","):
            self.finding.unsaved_vulnerability_ids.append(cve)

    def _handle_nvt_oid(self, column_value: str):
        self.finding.vuln_id_from_tool = column_value

    def _handle_hostname(self, column_value: str):
        # strip due to https://github.com/greenbone/gvmd/issues/2378
        get_location(self.finding).host = column_value.strip()

    def _handle_ip(self, column_value: str):
        # fallback to ip if hostname is not aviable
        if not get_location(self.finding).host:
            # strip due to https://github.com/greenbone/gvmd/issues/2378
            get_location(self.finding).host = column_value.strip()

    def _handle_port(self, column_value: str):
        if column_value.isdigit():
            get_location(self.finding).port = int(column_value)

    def _handle_port_protocol(self, column_value: str):
        get_location(self.finding).protocol = column_value

    def _handle_severity(self, column_value: str):
        if is_valid_severity(column_value):
            self.finding.severity = column_value

    def _handle_cvss(self, column_value: str):
        self.aux_info.fallback_cvss_score = float(column_value)

    def _handle_summary(self, column_value: str):
        self.aux_info.summary = column_value

    def _handle_solution(self, column_value: str):
        self.finding.mitigation = cleanup_openvas_text(column_value)

    def _handle_vulnerability_insight(self, column_value: str):
        self.finding.impact = cleanup_openvas_text(column_value)

    def _handle_specific_result(self, column_value: str):
        self.aux_info.openvas_result = column_value

    def _handle_qod(self, column_value: str):
        self.aux_info.qod = column_value

    def _handle_epss_score(self, column_value: str):
        self.finding.epss_score = float(column_value)

    def _handle_epss_percentile(self, column_value: str):
        self.finding.epss_percentile = float(column_value)

    def _handle_timestamp(self, column_value: str):
        self.finding.date = parse_date(column_value).date()

    def _handle_references(self, column_value: str):
        self.aux_info.references = column_value.split(",")

    def _handle_active(self, column_value: str):
        self.finding.active = self._str_to_bool(column_value)

    def _handle_verified(self, column_value: str):
        self.finding.verified = self._str_to_bool(column_value)

    def _handle_falsepositive(self, column_value: str):
        self.finding.false_p = self._str_to_bool(column_value)

    def _handle_duplicate(self, column_value: str):
        self.finding.duplicate = self._str_to_bool(column_value)

    def _str_to_bool(self, column_value: str) -> bool | None:
        """Converts string to bool or None"""
        value = column_value.lower()
        if value == "true":
            return True
        if value == "false":
            return False
        return None
