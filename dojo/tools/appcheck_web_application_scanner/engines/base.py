import re
from typing import Any, Optional, Tuple, Union

import cvss.parser
from cpe import CPE

from dojo.models import Endpoint, Finding


class FieldType:
    def __init__(self):
        pass

    def handle(self, engine_class, finding, value):
        pass

    def __call__(self, engine_class, finding, value):
        self.handle(engine_class, finding, value)


class Attribute(FieldType):
    def __init__(self, attribute):
        super().__init__()
        self.attribute = attribute

    def handle(self, engine_class, finding, value):
        setattr(finding, self.attribute, value)


class Method(FieldType):
    def __init__(self, method_name):
        super().__init__()
        self.method_name = method_name

    def handle(self, engine_parser, finding, value):
        getattr(engine_parser, self.method_name)(finding, value)


class BaseEngineParser:
    """
    Parser for data shared by all engines used by AppCheck, as well as data from an unknown/unspecified engine.

    Directly mapped attributes, from JSON object -> Finding attribute:
        * _id -> unique_id_from_tool
        * title -> title
        * description -> description
        * first_detected_at -> date
        * solution -> mitigation
        * cvss_v3_vector -> cvssv3
        * epss_base_score -> epss_score

    Data mapped with a bit of tinkering, JSON object -> Finding attribute:
        * status -> active/false_p/risk_accepted (depending on value)
        * cves -> unsaved_vulnerability_ids (vulnerability_ids)
        * cpe -> component name/version
        * cvss_vector -> severity (determined using CVSS package)
        * notes -> appended to Finding description
        * details -> appended to Finding description

    Child classes can override the _ENGINE_FIELDS_MAP dictionary to support extended/different functionality as so
    desired, without having to change/copy the common field parsing described above.
    """
    SCANNING_ENGINE = "Unknown"

    # Field handling common to all findings returned by AppCheck
    _COMMON_FIELDS_MAP: dict[str, FieldType] = {
        "_id": Attribute("unique_id_from_tool"),
        "title": Attribute("title"),
        "description": Attribute("description"),
        "first_detected_at": Attribute("date"),
        "solution": Attribute("mitigation"),
        "cvss_v3_vector": Attribute("cvssv3"),
        "epss_base_score": Attribute("epss_score"),
        "status": Method("parse_status"),
        "cves": Method("parse_cves"),
        "cpe": Method("parse_components"),
        "cvss_vector": Method("parse_severity"),
        # These should be listed after the 'description' entry; they append to it
        "notes": Method("parse_notes"),
        "details": Method("parse_details")}

    # Field handling specific to a given scanning_engine AppCheck uses
    _ENGINE_FIELDS_MAP: dict[str, FieldType] = {}

    #####
    # For parsing CVEs
    #####
    CVE_PATTERN = re.compile("CVE-[0-9]+-[0-9]+", re.IGNORECASE)

    def is_cve(self, c: str) -> bool:
        return bool(c and self.CVE_PATTERN.fullmatch(c))

    def parse_cves(self, finding: Finding, value: [str]) -> None:
        finding.unsaved_vulnerability_ids = [c.upper() for c in value if self.is_cve(c)]

    #####
    # Handles setting various status flags on the Finding
    #####
    def parse_status(self, finding: Finding, value: str) -> None:
        # (Supposed) values:
        # unfixed (the initial value), fixed, false_positive, and acceptable_risk
        value = value.lower()
        if value == "fixed":
            finding.active = False
        elif value == "false_positive":
            finding.false_p = True
        elif value == "acceptable_risk":
            finding.risk_accepted = True

    #####
    # For severity (extracted from cvss vector)
    #####
    def parse_severity(self, finding: Finding, value: str) -> None:
        if cvss_obj := cvss.parser.parse_cvss_from_text(value):
            severity = cvss_obj[0].severities()[0]
            if severity.lower() != "none":
                finding.severity = severity

    #####
    # For parsing component data
    #####
    def parse_cpe(self, cpe_str: str) -> (Optional[str], Optional[str]):
        cpe_obj = CPE(cpe_str)
        return (
            cpe_obj.get_product() and cpe_obj.get_product()[0] or None,
            cpe_obj.get_version() and cpe_obj.get_version()[0] or None,
        )

    def parse_components(self, finding: Finding, value: [str]) -> None:
        # Only use the first entry
        finding.component_name, finding.component_version = self.parse_cpe(value[0])

    #####
    # For parsing additional description-related entries (notes and details)
    #####
    def format_additional_description(self, section: str, value: str) -> str:
        return f"**{section}**: {value}"

    def append_description(self, finding: Finding, addendum: dict[str, str]) -> None:
        if addendum:
            if finding.description:
                finding.description += "\n\n"
            finding.description += "\n\n".join([self.format_additional_description(k, v) for k, v in addendum.items()])

    def parse_notes(self, finding: Finding, value: str) -> None:
        self.append_description(finding, {"Notes": value})

    def extract_details(self, value: Union[str, dict[str, Union[str, dict[str, [str]]]]]) -> dict[str, str]:
        if isinstance(value, dict):
            return {k: v for k, v in value.items() if k != "_meta"}
        return {"Details": str(value)}

    def parse_details(self, finding: Finding, value: dict[str, Union[str, dict[str, [str]]]]) -> None:
        self.append_description(finding, self.extract_details(value))

    #####
    # For parsing endpoints
    #####
    def get_host(self, item: dict[str, Any]) -> str:
        return item.get("url") or item.get("host") or item.get("ipv4_address")

    def get_port(self, item: dict[str, Any]) -> Optional[int]:
        return item.get("port")

    def construct_endpoint(self, host: str, port: int) -> Endpoint:
        endpoint = Endpoint.from_uri(host)
        if endpoint.host:
            if port:
                endpoint.port = port
        else:
            endpoint = Endpoint(host=host, port=port)
        return endpoint

    def parse_endpoints(self, item: dict[str, Any]) -> [Endpoint]:
        host = self.get_host(item)
        port = self.get_port(item)
        return [self.construct_endpoint(host, port)]

    def set_endpoints(self, finding: Finding, item: Any) -> None:
        endpoints = self.parse_endpoints(item)
        finding.unsaved_endpoints.extend(endpoints)

    # Returns the complete field processing map: common fields plus any engine-specific
    def get_engine_fields(self) -> dict[str, FieldType]:
        return {
            **BaseEngineParser._COMMON_FIELDS_MAP,
            **self._ENGINE_FIELDS_MAP}

    def get_finding_key(self, finding: Finding) -> Tuple:
        return (
            finding.severity,
            finding.title,
            tuple(sorted([(e.host, e.port) for e in finding.unsaved_endpoints])),
            self.SCANNING_ENGINE,
        )

    def parse_finding(self, item: dict[str, Any]) -> Tuple[Finding, Tuple]:
        finding = Finding()
        for field, field_handler in self.get_engine_fields().items():
            # Check first whether the field even exists on this item entry; if not, skip it
            if value := item.get(field):
                field_handler(self, finding, value)
        self.set_endpoints(finding, item)
        # Make a note of what scanning engine was used for this Finding
        self.append_description(finding, {"Scanning Engine": self.SCANNING_ENGINE})
        return finding, self.get_finding_key(finding)
