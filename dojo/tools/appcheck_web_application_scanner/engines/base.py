import re
from itertools import starmap
from typing import Any, Optional, Tuple, Union

import cvss.parser
import dateutil.parser
from cpe import CPE
from cvss.exceptions import CVSSError
from django.core.exceptions import ImproperlyConfigured

from dojo.models import Endpoint, Finding

#######
# Helpers/Utils
#######

# Pattern for stripping markup from entry values -- removes "[[markup]]" and "[[" and "]]"
MARKUP_STRIPPING_PATTERN = re.compile(r"\[\[markup\]\]|\[\[|\]\]")


def strip_markup(value: str) -> str:
    """Strips out "markup" from value"""
    if value:
        return MARKUP_STRIPPING_PATTERN.sub("", value).strip()
    return value


def escape_non_printable(s: str) -> str:
    """
    Replaces non-printable characters from a string, for some definition of non-printable that probably differs from the
    uncountable other available definitions of non-printable, with a more-printable version.
    """
    def escape_if_needed(x):
        # Accept isprintable() stuff (which includes space) and common whitespaces that can be rendered
        if x.isprintable() or x in {"\r", "\n", "\t"}:
            return x
        # Anything else -- including other weird whitespaces -- use repr() to give the string representation; also
        # remove the surrounding single quotes
        return repr(x)[1:-1]
    return "".join([escape_if_needed(c) for c in s])


def cvss_score_to_severity(score: float, version: int) -> str:
    """
    Maps a CVSS score with a given version to a severity level.
    Mapping from https://nvd.nist.gov/vuln-metrics/cvss (modified slightly to have "Info" in range [0.0, 0.1) for CVSS
        v3/v4)
    """
    cvss_score = float(score)
    if version == 2:
        if cvss_score >= 7.0:
            severity = "High"
        elif cvss_score >= 4.0:
            severity = "Medium"
        else:
            severity = "Low"
    else:
        if cvss_score >= 9.0:
            severity = "Critical"
        elif cvss_score >= 7.0:
            severity = "High"
        elif cvss_score >= 4.0:
            severity = "Medium"
        elif cvss_score >= 0.1:
            severity = "Low"
        else:
            severity = "Info"

    return severity


#######
# Field parsing helper classes
#######
class FieldType:

    """
    Base class for attribute handlers for parsers. Callable, and calls the .handle() method, which should be implemented
    by subclasses.

    We lose type safety by accepting strings for target names; to try to work around this, the check() method on
    subclasses should check whether the configuration for this object makes sense (or as much sense as can be determined
    when the method is called) and raise an ImproperlyConfigured exception if it does not.
    """

    def __init__(self, target_name):
        self.target_name = target_name

    def handle(self, engine_class, finding, value):
        pass

    def __call__(self, engine_class, finding, value):
        self.handle(engine_class, finding, value)

    def check(self, engine_parser):
        pass


class Attribute(FieldType):

    """
    Class for a field that maps directly from one in the input data to a Finding attribute. Initialized with a Finding
    attribute name, when called sets the value of that attribute to the passed-in value.
    """

    def handle(self, engine_class, finding, value):
        setattr(finding, self.target_name, value)

    def check(self, engine_parser):
        if not hasattr(Finding, self.target_name):
            msg = f"Finding does not have attribute '{self.target_name}.'"
            raise ImproperlyConfigured(msg)


class DeMarkupedAttribute(Attribute):

    """Class for an Attribute (as above) but whose value is stripped of markup and non-printable chars prior to being set."""

    def handle(self, engine_class, finding, value):
        super().handle(engine_class, finding, escape_non_printable(strip_markup(value)))


class Method(FieldType):

    """
    Class for a field that requires a method to process it. Initialized with a method name, when called it invokes the
    method on the passed-in engine parser, passing in a Finding and value. It's expected that the method will update
    the Finding as it sees fit (i.e., this class does not modify the Finding)
    """

    def handle(self, engine_parser, finding, value):
        getattr(engine_parser, self.target_name)(finding, value)

    def check(self, engine_parser):
        if not callable(getattr(engine_parser, self.target_name, None)):
            msg = f"{type(engine_parser).__name__} does not have method '{self.target_name}().'"
            raise ImproperlyConfigured(msg)


class BaseEngineParser:

    """
    Parser for data shared by all engines used by AppCheck, as well as data from an unknown/unspecified engine.

    Directly mapped attributes, from JSON object -> Finding attribute:
        * _id -> unique_id_from_tool
        * cvss_v3_vector -> cvssv3
        * epss_base_score -> epss_score

    Directly mapped attributes but value is stripped of "markup" first, JSON Object -> Finding attribute:
        * title -> title
        * description -> description
        * solution -> mitigation

    Data mapped with a bit of tinkering, JSON object -> Finding attribute:
        * first_detected_at -> date (parse date)
        * status -> active/false_p/risk_accepted (depending on value)
        * cves -> unsaved_vulnerability_ids (vulnerability_ids)
        * cpe -> component name/version
        * notes -> appended to Finding description
        * details -> appended to Finding description

    Child classes can override the _ENGINE_FIELDS_MAP dictionary to support extended/different functionality as so
    desired, without having to change/copy the common field parsing described above.
    """

    SCANNING_ENGINE = "Unknown"

    # Field handling common to all findings returned by AppCheck
    _COMMON_FIELDS_MAP: dict[str, FieldType] = {
        "_id": Attribute("unique_id_from_tool"),
        "cvss_v3_vector": Attribute("cvssv3"),
        "epss_base_score": Attribute("epss_score"),
        "title": DeMarkupedAttribute("title"),
        "description": DeMarkupedAttribute("description"),
        "solution": DeMarkupedAttribute("mitigation"),
        "first_detected_at": Method("parse_initial_date"),
        "status": Method("parse_status"),
        "cves": Method("parse_cves"),
        "cpe": Method("parse_components"),
        # These should be listed after the 'description' entry; they append to it
        "notes": Method("parse_notes"),
        "details": Method("parse_details")}

    # Field handling specific to a given scanning_engine AppCheck uses
    _ENGINE_FIELDS_MAP: dict[str, FieldType] = {}

    def __init__(self):
        # Do a basic check that the fields we'll process over are valid
        for field_handler in self.get_engine_fields().values():
            field_handler.check(self)

    #####
    # For parsing the initial finding datetime to a date format pleasing to Finding
    #####
    def get_date(self, value: str) -> Optional[str]:
        try:
            return str(dateutil.parser.parse(value).date())
        except dateutil.parser.ParserError:
            return None

    def parse_initial_date(self, finding: Finding, value: str) -> None:
        finding.date = self.get_date(value)

    #####
    # For parsing CVEs
    #####
    CVE_PATTERN = re.compile("CVE-[0-9]+-[0-9]+", re.IGNORECASE)

    def is_cve(self, c: str) -> bool:
        return bool(c and isinstance(c, str) and self.CVE_PATTERN.fullmatch(c))

    def parse_cves(self, finding: Finding, value: list[str]) -> None:
        finding.unsaved_vulnerability_ids = [c.upper() for c in value if self.is_cve(c)]

    #####
    # Handles setting various status flags on the Finding
    #####
    def parse_status(self, finding: Finding, value: str) -> None:
        # Possible values (best guess): unfixed (the initial value), fixed, false_positive, and acceptable_risk
        value = value.lower()
        if value == "fixed":
            finding.active = False
        elif value == "false_positive":
            finding.false_p = True
        elif value == "acceptable_risk":
            finding.risk_accepted = True

    #####
    # For parsing component data
    #####
    def parse_cpe(self, cpe_str: str) -> (Optional[str], Optional[str]):
        if not cpe_str:
            return None, None
        cpe_obj = CPE(cpe_str)
        return (
            (cpe_obj.get_product() and cpe_obj.get_product()[0]) or None,
            (cpe_obj.get_version() and cpe_obj.get_version()[0]) or None,
        )

    def parse_components(self, finding: Finding, value: list[str]) -> None:
        # Only use the first entry
        finding.component_name, finding.component_version = self.parse_cpe(value[0])

    #####
    # For parsing additional description-related entries (description, notes, and details)
    #####
    def format_additional_description(self, section: str, value: str) -> str:
        return f"**{section}**: {escape_non_printable(strip_markup(value))}"

    def append_description(self, finding: Finding, addendum: dict[str, str]) -> None:
        if addendum:
            if finding.description:
                finding.description += "\n\n"
            finding.description += "\n\n".join(list(starmap(self.format_additional_description, addendum.items())))

    def parse_notes(self, finding: Finding, value: str) -> None:
        self.append_description(finding, {"Notes": value})

    def extract_details(self, value: Union[str, dict[str, Union[str, dict[str, list[str]]]]]) -> dict[str, str]:
        if isinstance(value, dict):
            return {k: v for k, v in value.items() if k != "_meta"}
        return {"Details": str(value)}

    def parse_details(self, finding: Finding, value: dict[str, Union[str, dict[str, list[str]]]]) -> None:
        self.append_description(finding, self.extract_details(value))

    #####
    # For parsing endpoints
    #####
    def get_host(self, item: dict[str, Any]) -> str:
        return item.get("url") or item.get("host") or item.get("ipv4_address") or None

    def parse_port(self, item: Any) -> Optional[int]:
        try:
            int_val = int(item)
            if 0 < int_val <= 65535:
                return int_val
        except (ValueError, TypeError):
            pass
        return None

    def get_port(self, item: dict[str, Any]) -> Optional[int]:
        return self.parse_port(item.get("port"))

    def construct_endpoint(self, host: str, port: Optional[int]) -> Endpoint:
        endpoint = Endpoint.from_uri(host)
        if endpoint.host:
            if port:
                endpoint.port = port
        else:
            endpoint = Endpoint(host=host, port=port)
        return endpoint

    def parse_endpoints(self, item: dict[str, Any]) -> [Endpoint]:
        # Endpoint requires a host
        if host := self.get_host(item):
            port = self.get_port(item)
            return [self.construct_endpoint(host, port)]
        return []

    def set_endpoints(self, finding: Finding, item: Any) -> None:
        endpoints = self.parse_endpoints(item)
        finding.unsaved_endpoints.extend(endpoints)

    #####
    # For severity (extracted from various cvss vectors)
    #####
    def parse_cvss_vector(self, value: str) -> Optional[str]:
        # CVSS4 vectors don't parse with the handy-danty parse method :(
        try:
            if (severity := cvss.CVSS4(value).severity) in Finding.SEVERITIES:
                return severity
        except CVSSError:
            pass

        if cvss_obj := cvss.parser.parse_cvss_from_text(value):
            if (severity := cvss_obj[0].severities()[0].title()) in Finding.SEVERITIES:
                return severity
        return None

    def set_severity(self, finding: Finding, item: Any) -> None:
        for base_score_entry, cvss_version in [
            ("cvss_v4_base_score", 4),
            ("cvss_v3_base_score", 3),
            ("cvss_base_score", 2),
        ]:
            if base_score := item.get(base_score_entry):
                finding.severity = cvss_score_to_severity(base_score, cvss_version)
                return

        for vector_type in ["cvss_v4_vector", "cvss_v3_vector", "cvss_vector"]:
            if vector := item.get(vector_type):
                if severity := self.parse_cvss_vector(vector):
                    finding.severity = severity
                    return

        finding.severity = "Info"

    def process_whole_item(self, finding: Finding, item: Any) -> None:
        self.set_severity(finding, item)
        self.set_endpoints(finding, item)

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
        self.process_whole_item(finding, item)
        # Make a note of what scanning engine was used for this Finding
        self.append_description(finding, {"Scanning Engine": self.SCANNING_ENGINE})
        return finding, self.get_finding_key(finding)
