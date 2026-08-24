import hashlib
import json
import re
from contextlib import suppress
from datetime import UTC, datetime
from ipaddress import ip_address
from urllib.parse import urlparse

from dojo.location.feature import locations_enabled
from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

SEVERITY_BY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
    "information": "Info",
}
DEFAULT_SEVERITY = "Info"

# Used only when a report carries no severity label - a tenant that scores with CVSS rather than OWASP
# sends a bare number instead.
CVSS_CRITICAL_FLOOR = 9.0
CVSS_HIGH_FLOOR = 7.0
CVSS_MEDIUM_FLOOR = 4.0

# "04 Sep 2021" - the format Beagle stamps a report with.
REPORT_DATE_FORMAT = "%d %b %Y"

# The report-level keys Beagle's documentation does confirm. They are also the keys the finding-array
# search skips, so a confirmed field is never mistaken for the finding list.
REPORT_STRING_FIELDS = (
    "project_name",
    "application_name",
    "url",
    "generated_date",
    "approved_date",
)

# Plausible names for the finding array, in preference order. Beagle's reference cuts the real name out
# of its only sample, so these are tried first and the search then falls back to "the first array of
# objects in the document".
VULNERABILITY_ARRAY_KEYS = (
    "vulnerabilities",
    "signatures",
    "vulnerability_list",
    "issues",
    "findings",
    "results",
)

# Beagle publishes none of the per-finding field names either, so each is read from a set of plausible
# aliases, case-insensitively. The most plausible spelling leads each list, and the first alias that
# yields a usable value wins.
NAME_ALIASES = (
    "name", "title", "vulnerability_name", "vulnerabilityname", "signature", "signature_name",
    "vulnerability",
)
SEVERITY_ALIASES = (
    "severity", "risk", "risk_level", "risklevel", "severity_level", "severitylevel", "priority",
)
SCORE_ALIASES = ("cvss_score", "cvssscore", "score", "cvss", "risk_score", "riskscore")
VECTOR_ALIASES = ("cvss_vector", "cvssvector", "vector", "cvss")
CWE_ALIASES = ("cwe", "cwe_id", "cweid", "cwes")
DESCRIPTION_ALIASES = (
    "description", "details", "detail", "summary", "impact", "vulnerability_description",
)
REMEDIATION_ALIASES = (
    "remediation", "solution", "recommendation", "recommendations", "fix", "mitigation",
)
# Leads with the vendor's own one-"r" spelling, verbatim from their reference.
OCCURRENCE_ALIASES = ("occurences", "occurrences", "instances")

# Beagle's own spelling for the per-application id, from their projects response. An export that
# carries it gets connector-identical unique ids; see application_token().
APPLICATION_TOKEN_KEYS = ("applicationToken", "application_token", "applicationtoken")

STATUS_FIXED = "fixed"


# The host DefectDojo accepts: letters, digits, dot, hyphen, underscore or plus, at least two
# characters - or an IP address. See Endpoint.clean().
HOST_PATTERN = re.compile(r"^[A-Za-z0-9_\-+][A-Za-z0-9_.\-+]+$")


class BeagleParser:

    """
    Parses a Beagle Security test report.

    Mirrors pkg/tools/beagle/converter field for field so a file import and an API sync deduplicate
    against each other instead of producing two copies of everything.

    Beagle does not publish the schema of the report body. The report-level keys and the occurrence
    block are documented; the per-finding field names are not, so - exactly like the connector - every
    finding field is read from a set of plausible aliases and the finding array is located by name or,
    failing that, by shape. See extract() and the *_ALIASES tables.

    Note the deduplication configuration for this scan type hashes the ENDPOINTS, so the tested URL has
    to be populated or the hash is computed over nothing.
    """

    def get_scan_types(self):
        # Byte-identical to the connector's ScanType().
        return ["Beagle Security - Connectors Import"]

    def get_label_for_scan_types(self, scan_type):
        return "Beagle Security - Connectors Import"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Beagle Security test report (JSON). Matches the scan type used by the Beagle "
            "Security connector so file and API findings deduplicate. Both the report body and the "
            "API envelope that carries it are accepted."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Beagle Security Parser.

        Mirrors the connector's finding():
        - title: the finding name, else "Beagle Security finding (<CWE>)", else a bare label.
        - severity: the severity label, else graded from the CVSS score; see severity().
        - description: the finding prose, then the method, URL, Beagle status and CWE.
        - mitigation: the remediation text.
        - cvssv3 / cvssv3_score: the CVSS vector and score when the tenant scores with CVSS.
        - active / is_mitigated: an occurrence Beagle calls "Fixed" is imported as mitigated.
        - unique_id_from_tool: see unique_id() - present only when the export carries the token.
        - vuln_id_from_tool: the finding name, which is Beagle's signature identifier.
        - param: the HTTP method the occurrence was found with.
        """
        return [
            "title",
            "severity",
            "date",
            "description",
            "mitigation",
            "cwe",
            "cvssv3",
            "cvssv3_score",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "param",
            "tags",
            "active",
            "is_mitigated",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Beagle Security Parser.

        Copied from the Beagle Security block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. Note endpoints is among them, so the
        tested URL must be populated for the hash to mean anything - and it is the hash, not the unique
        id, that bridges a file import to an API sync when the export carries no application token.
        """
        return ["title", "severity", "endpoints"]

    def get_findings(self, filename, test):
        data = json.load(filename)
        report = self.report(data)
        vulnerabilities = self.extract(report)
        token = self.application_token(data, report)
        # The connector stamps every finding in a report with the report's own date.
        date = self.report_date(report)
        target = (report.get("url") or "").strip()

        findings = []
        for item in vulnerabilities:
            if isinstance(item, dict):
                findings.extend(self.vulnerability_findings(item, target, token, date, test))
        return findings

    def report(self, data):
        """
        Return the report body.

        Beagle returns the report as a JSON *string* inside an envelope - {"result": "{...}"} - so an
        export is either the envelope or the report body it carries.
        """
        if isinstance(data, dict):
            result = data.get("result")
            if isinstance(result, str) and result.strip():
                with suppress(ValueError):
                    decoded = json.loads(result)
                    if isinstance(decoded, dict):
                        return decoded
            if isinstance(result, dict):
                return result
            return data

        msg = (
            "A Beagle Security export is a test report, a JSON object carrying the report keys and a "
            f"list of findings; got {type(data).__name__}."
        )
        raise TypeError(msg)

    def extract(self, report):
        """
        Return the report's finding list.

        Beagle's reference cuts the finding array's name out of its only sample, so it is looked up by
        the plausible names first and then by shape: the first key, in sorted order, whose value is an
        array of objects. Sorting keeps the choice deterministic rather than dict-order dependent.
        """
        for candidate in VULNERABILITY_ARRAY_KEYS:
            if self.is_array_of_objects(report.get(candidate)):
                return report[candidate]

        for key in sorted(report):
            if key in REPORT_STRING_FIELDS:
                continue
            if self.is_array_of_objects(report.get(key)):
                return report[key]

        if not any(key in report for key in REPORT_STRING_FIELDS):
            msg = (
                "This file carries neither Beagle Security's report keys (project_name, "
                "application_name, url, generated_date, approved_date) nor a list of findings."
            )
            raise TypeError(msg)
        # A report Beagle produced with nothing to report. The connector logs the keys it saw and
        # returns no findings rather than treating it as an error.
        return []

    def is_array_of_objects(self, value):
        """Whether value is a JSON array whose first element is an object."""
        if not isinstance(value, list):
            return False
        for item in value:
            return isinstance(item, dict)
        return False

    def application_token(self, data, report):
        """
        Return the application token, if the export carries one.

        The connector always has it - it is the parameter every Beagle API call takes - and hashes it
        into the unique id. A report body does not carry it, so an export usually has none, and then no
        unique id is set at all: a token-less hash would collide with nothing the connector produced,
        whereas leaving it unset lets this scan type's other deduplication key, the hash over title,
        severity and endpoints, match the API findings instead.
        """
        for source in (report, data):
            if not isinstance(source, dict):
                continue
            for key in APPLICATION_TOKEN_KEYS:
                value = source.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        return ""

    def report_date(self, report):
        """The report's generated date, then its approved date, then today."""
        for key in ("generated_date", "approved_date"):
            value = report.get(key)
            if isinstance(value, str):
                with suppress(ValueError):
                    return datetime.strptime(value.strip(), REPORT_DATE_FORMAT).replace(tzinfo=UTC).date()
        return datetime.now(tz=UTC).date()

    def vulnerability_findings(self, item, target, token, date, test):
        """
        One finding per occurrence.

        An occurrence is one place the finding was observed - a method and a URL - so a finding
        reported on three URLs is three findings. A finding with no occurrences still gets one, aimed
        at the application's own URL.
        """
        fields = {str(key).strip().lower(): value for key, value in item.items()}
        vulnerability = self.vulnerability(fields, item)

        occurrences = self.occurrences(fields)
        if not occurrences:
            return [self.build_finding(vulnerability, None, target, token, date, test)]
        return [
            self.build_finding(vulnerability, occurrence, target, token, date, test)
            for occurrence in occurrences
        ]

    def vulnerability(self, fields, item):
        """Resolve one finding's fields through the alias tables."""
        label, score = self.severity_fields(fields)
        if better := self.first_number(fields, SCORE_ALIASES):
            score = better
        return {
            "name": self.first_string(fields, NAME_ALIASES),
            "severity_label": label,
            "score": score,
            "vector": self.first_vector(fields),
            "cwe": self.first_scalar(fields, CWE_ALIASES),
            "description": self.first_string(fields, DESCRIPTION_ALIASES),
            "remediation": self.first_string(fields, REMEDIATION_ALIASES),
            "keys": sorted(str(key) for key in item),
        }

    def occurrences(self, fields):
        for alias in OCCURRENCE_ALIASES:
            value = fields.get(alias)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return []

    def build_finding(self, vulnerability, occurrence, target, token, date, test):
        method, endpoint = self.occurrence_target(occurrence, target)
        fixed = self.is_fixed(occurrence)

        finding = Finding(
            test=test,
            title=self.title(vulnerability),
            severity=self.severity(vulnerability),
            date=date,
            description=self.describe(vulnerability, occurrence),
            mitigation=vulnerability["remediation"],
            active=occurrence is None or not fixed,
            is_mitigated=occurrence is not None and fixed,
            # Beagle Security drives a browser against a running application.
            static_finding=False,
            dynamic_finding=True,
            vuln_id_from_tool=vulnerability["name"] or None,
            param=method or None,
        )
        finding.unsaved_tags = self.tags(vulnerability)

        if vector := vulnerability["vector"]:
            finding.cvssv3 = vector
        if vulnerability["score"] > 0:
            finding.cvssv3_score = vulnerability["score"]
        if (cwe := self.cwe_number(vulnerability["cwe"])) is not None:
            finding.cwe = cwe
        if unique_id := self.unique_id(token, vulnerability["name"], method, endpoint):
            finding.unique_id_from_tool = unique_id

        self.attach_endpoint(finding, endpoint)
        return finding

    def occurrence_target(self, occurrence, target):
        """
        The method and URL an occurrence was found at.

        A finding with no occurrence is aimed at the application's own URL, and an occurrence missing
        its URL falls back to the same.
        """
        if occurrence is None:
            return "", target

        nested = occurrence.get("vulnerability")
        nested = nested if isinstance(nested, dict) else {}
        # Beagle really does capitalise these two, verbatim from their documentation.
        method = str(nested.get("Method") or "").strip().upper()
        endpoint = str(nested.get("Url") or "").strip()
        return method, endpoint or target

    def is_fixed(self, occurrence):
        """
        Whether Beagle considers this occurrence remediated.

        "Fixed" is the one status value their documentation shows; the rest of the enum is unpublished,
        so anything else counts as open.
        """
        if occurrence is None:
            return False
        return str(occurrence.get("status") or "").strip().lower() == STATUS_FIXED

    def title(self, vulnerability):
        if name := vulnerability["name"]:
            return name
        if cwe := vulnerability["cwe"]:
            return f"Beagle Security finding ({cwe})"
        return "Beagle Security finding"

    def severity(self, vulnerability):
        """
        Grade the finding.

        The severity label wins when there is one, and an unrecognised label is Info rather than a
        guess. A tenant that scores reports with CVSS instead sends a bare number, which is graded
        against the CVSS floors. Neither means Info.
        """
        if label := vulnerability["severity_label"]:
            return SEVERITY_BY_LABEL.get(label.lower(), DEFAULT_SEVERITY)

        score = vulnerability["score"]
        if score > 0:
            if score >= CVSS_CRITICAL_FLOOR:
                return "Critical"
            if score >= CVSS_HIGH_FLOOR:
                return "High"
            if score >= CVSS_MEDIUM_FLOOR:
                return "Medium"
            return "Low"
        return DEFAULT_SEVERITY

    def describe(self, vulnerability, occurrence):
        sections = []
        if description := vulnerability["description"]:
            sections.append(description)

        details = []
        if occurrence is not None:
            nested = occurrence.get("vulnerability")
            nested = nested if isinstance(nested, dict) else {}
            if method := str(nested.get("Method") or "").strip().upper():
                details.append(f"**Method:** {method}")
            if url := str(nested.get("Url") or "").strip():
                details.append(f"**URL:** {url}")
            if status := str(occurrence.get("status") or "").strip():
                details.append(f"**Beagle status:** {status}")
        if cwe := vulnerability["cwe"]:
            details.append(f"**CWE:** {cwe}")

        if details:
            sections.append("\n".join(details))
        return "\n\n".join(sections)

    def tags(self, vulnerability):
        tags = ["beagle-security"]
        if label := vulnerability["severity_label"]:
            tags.append(label)
        return tags

    def unique_id(self, token, name, method, endpoint):
        """
        The connector's identity: sha256 of the application token, name, method and URL.

        Computed only when the export carries the token - see application_token() - because an id
        hashed over a token the connector never used would deduplicate against nothing.
        """
        if not token:
            return ""
        digest = hashlib.sha256(f"{token}|{name}|{method}|{endpoint}".encode())
        return digest.hexdigest()

    def cwe_number(self, cwe):
        """Read a CWE id off "CWE-215", "215", or the first entry of "215, 216"."""
        trimmed = cwe.strip()
        for prefix in ("CWE-", "cwe-"):
            trimmed = trimmed.removeprefix(prefix)
        for separator in (",", " "):
            index = trimmed.find(separator)
            if index > 0:
                trimmed = trimmed[:index]
        with suppress(ValueError):
            number = int(trimmed)
            if number > 0:
                return number
        return None

    def attach_endpoint(self, finding, url):
        """
        Record the URL the finding was reported against.

        This scan type's deduplication hashes the endpoints, so an unpopulated endpoint would leave
        the hash computed over nothing and every rescan would reimport.
        """
        if not url:
            return
        with suppress(ValueError):
            parsed = urlparse(url)
            if not parsed.hostname or not self.usable_host(parsed.hostname):
                return
            if locations_enabled():
                finding.unsaved_locations.append(LocationData.url(
                    host=parsed.hostname, protocol=parsed.scheme or None, port=parsed.port,
                    path=parsed.path.lstrip("/"), query=parsed.query,
                ))
            else:
                # TODO: Delete this after the move to Locations
                finding.unsaved_endpoints.append(Endpoint(
                    host=parsed.hostname, protocol=parsed.scheme or None, port=parsed.port,
                    path=parsed.path.lstrip("/") or None, query=parsed.query or None,
                ))

    def usable_host(self, value):
        """
        Whether DefectDojo will accept this as an endpoint host.

        A host is letters, digits, dot, hyphen, underscore or plus, or an IP address. Anything else -
        a path, a space, a container image tag - makes Endpoint.clean() raise, and that fails the
        whole import rather than the one finding, so it is dropped here instead. The value is still
        reported in the description, so nothing is lost.
        """
        if HOST_PATTERN.match(value):
            return True
        with suppress(ValueError):
            ip_address(value)
            return True
        return False

    def first_string(self, fields, aliases):
        """The first alias holding a non-empty string."""
        for alias in aliases:
            value = fields.get(alias)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""

    def first_number(self, fields, aliases):
        """The first alias holding a number, accepting a numeric string too."""
        for alias in aliases:
            value = fields.get(alias)
            if isinstance(value, bool):
                continue
            if isinstance(value, int | float):
                return float(value)
            if isinstance(value, str):
                with suppress(ValueError):
                    return float(value.strip())
        return 0.0

    def first_scalar(self, fields, aliases):
        """
        The first alias holding a string, a number, or a list of them, rendered as a string.

        A CWE id in particular arrives any of those ways.
        """
        if value := self.first_string(fields, aliases):
            return value
        for alias in aliases:
            value = fields.get(alias)
            if isinstance(value, bool):
                continue
            if isinstance(value, int | float):
                return str(value)
            if isinstance(value, list):
                rendered = [str(item).strip() for item in value if str(item).strip()]
                if rendered:
                    return ", ".join(rendered)
        return ""

    def severity_fields(self, fields):
        """
        The severity, which Beagle renders either as a label or - when the tenant scores reports with
        CVSS rather than OWASP - as a number under the same key.
        """
        if label := self.first_string(fields, SEVERITY_ALIASES):
            return label, 0.0
        return "", self.first_number(fields, SEVERITY_ALIASES)

    def first_vector(self, fields):
        """A CVSS vector, which is distinguishable from a score by its "CVSS:" prefix."""
        for alias in VECTOR_ALIASES:
            value = fields.get(alias)
            if isinstance(value, str) and value.strip().upper().startswith("CVSS:"):
                return value.strip()
        return ""
