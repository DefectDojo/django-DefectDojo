import json
import logging
from datetime import UTC, datetime

from dojo.models import Finding

logger = logging.getLogger(__name__)

SCAN_TYPE = "Datadog dd-trace IAST JSON"

# Every vulnerability type the dd-trace IAST reports (ddtrace/appsec/_iast/constants.py), with a
# severity and the CWE it describes. The tracer reports no severity of its own. A type missing here
# imports as Info without a CWE: that is a mapping gap to fix, never a reason to guess upward.
VULNERABILITY_TYPES = {
    "SQL_INJECTION": ("High", 89),
    "COMMAND_INJECTION": ("High", 78),
    "CODE_INJECTION": ("High", 94),
    "HEADER_INJECTION": ("High", 113),
    "PATH_TRAVERSAL": ("High", 22),
    "SSRF": ("High", 918),
    "XSS": ("High", 79),
    "UNTRUSTED_DESERIALIZATION": ("High", 502),
    "UNVALIDATED_REDIRECT": ("Medium", 601),
    "WEAK_HASH": ("Medium", 328),
    "WEAK_CIPHER": ("Medium", 327),
    "WEAK_RANDOMNESS": ("Medium", 330),
    "INSECURE_COOKIE": ("Medium", 614),
    "NO_HTTPONLY_COOKIE": ("Medium", 1004),
    "NO_SAMESITE_COOKIE": ("Medium", 1275),
    "STACKTRACE_LEAK": ("Low", 209),
}
UNKNOWN_TYPE = ("Info", None)

REDACTED = "[redacted]"
TAG = "ddtrace-iast"


class NotAnIastReportError(ValueError):

    """The file is not a dd-trace IAST JSON report; a ValueError so the importer shows the hint."""


class DdtraceIastParser:

    """
    Parses the IAST reports the open-source dd-trace tracers attach to spans.

    With IAST enabled, a tracer writes no report file: each span that reached a vulnerable sink with
    tainted data carries a report in meta_struct["iast"]. The importable file is a JSON array of
    span records, each holding that decoded report under "iast" next to the span's service, env,
    resource, trace_id, span_id and start.

    The tracer computes each vulnerability's hash from its type and code location, so a thousand
    requests hitting one bug report one hash. Within a file, repeats of the same (service, hash)
    become a single finding whose nb_occurences counts them.
    """

    def get_scan_types(self):
        return [SCAN_TYPE]

    def get_label_for_scan_types(self, scan_type):
        return SCAN_TYPE

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import IAST vulnerabilities reported by the open-source Datadog tracers (dd-trace), as a "
            "JSON array of span records carrying the decoded meta_struct iast report."
        )

    def get_findings(self, file, test):
        records = load_records(file)
        findings = {}
        for index, record in enumerate(records):
            for vulnerability in iast_report(record, index).get("vulnerabilities") or []:
                if isinstance(vulnerability, dict):
                    add_occurrence(findings, record, vulnerability, test)
        if not findings:
            logger.info("dd-trace IAST report holds no vulnerabilities")
        return list(findings.values())


def load_records(file):
    try:
        records = json.load(file)
    except ValueError as error:
        msg = f"Not a dd-trace IAST JSON report: {error}"
        raise NotAnIastReportError(msg) from error
    if not isinstance(records, list):
        msg = "A dd-trace IAST JSON report is an array of span records, each with an 'iast' object"
        raise NotAnIastReportError(msg)
    return records


def iast_report(record, index):
    report = record.get("iast") if isinstance(record, dict) else None
    if not isinstance(report, dict):
        msg = f"Record {index} of the dd-trace IAST report has no 'iast' object"
        raise NotAnIastReportError(msg)
    return report


def add_occurrence(findings, record, vulnerability, test):
    tracer_hash = vulnerability.get("hash")
    key = (record.get("service"), tracer_hash) if tracer_hash is not None else id(vulnerability)
    if key in findings:
        findings[key].nb_occurences += 1
    else:
        findings[key] = build_finding(record, vulnerability, test)


def build_finding(record, vulnerability, test):
    location = vulnerability.get("location") or {}
    vuln_type = str(vulnerability.get("type") or "UNKNOWN")
    severity, cwe = VULNERABILITY_TYPES.get(vuln_type, UNKNOWN_TYPE)
    tracer_hash = vulnerability.get("hash")
    finding = Finding(
        test=test,
        title=title(vuln_type, location),
        severity=severity,
        cwe=cwe,
        description=description(record, vulnerability, vuln_type, location),
        file_path=location.get("path") or None,
        line=location.get("line") or None,
        component_name=record.get("service") or None,
        static_finding=False,
        dynamic_finding=True,
        nb_occurences=1,
    )
    if tracer_hash is not None:
        finding.vuln_id_from_tool = str(tracer_hash)
    date = finding_date(record.get("start"))
    if date:
        finding.date = date
    finding.unsaved_tags = finding_tags(record.get("env"))
    return finding


def finding_date(start):
    """The span start, in nanoseconds since the epoch, as a date."""
    if isinstance(start, int) and start > 0:
        return datetime.fromtimestamp(start / 1e9, UTC).date()
    return None


def finding_tags(env):
    return [TAG, env] if env else [TAG]


def title(vuln_type, location):
    where = location.get("path") or location.get("method")
    if not where:
        return vuln_type
    line = location.get("line")
    return f"{vuln_type} in {where}:{line}" if line else f"{vuln_type} in {where}"


def description(record, vulnerability, vuln_type, location):
    report = record["iast"]
    fields = [
        ("Type", vuln_type),
        ("Evidence", render_evidence(vulnerability.get("evidence"))),
        ("Sources", ", ".join(referenced_sources(vulnerability.get("evidence"), report.get("sources")))),
        ("Route", record.get("resource")),
        ("File", location.get("path")),
        ("Line", location.get("line")),
        ("Function", location.get("method")),
        ("Service", record.get("service")),
        ("Environment", record.get("env")),
        ("Tracer hash", vulnerability.get("hash")),
        ("Trace ID", record.get("trace_id")),
        ("Span ID", record.get("span_id")),
    ]
    return "\n".join(f"**{name}:** {as_text(name, value)}" for name, value in fields if value not in {None, ""})


def as_text(name, value):
    return f"`{value}`" if name == "Evidence" else str(value)


def evidence_parts(evidence):
    """The evidence's valueParts, or None when the tracer sent the evidence as a single value."""
    parts = evidence.get("valueParts") if isinstance(evidence, dict) else None
    if not isinstance(parts, list):
        return None
    return [part for part in parts if isinstance(part, dict)]


def render_evidence(evidence):
    """Join the evidence parts the tracer sent; a redacted part shows only a placeholder."""
    parts = evidence_parts(evidence)
    if parts is None:
        return str(evidence.get("value") or "") if isinstance(evidence, dict) else ""
    return "".join(REDACTED if part.get("redacted") else str(part.get("value") or "") for part in parts)


def referenced_sources(evidence, sources):
    """Name the taint sources the evidence points at, as origin:name, never with their value."""
    sources = sources if isinstance(sources, list) else []
    labels = []
    for part in evidence_parts(evidence) or []:
        label = source_label(sources, part.get("source"))
        if label and label not in labels:
            labels.append(label)
    return labels


def source_label(sources, index):
    """origin:name of the source at index; None when the index points at nothing."""
    if not isinstance(index, int) or not 0 <= index < len(sources) or not isinstance(sources[index], dict):
        return None
    return f"{sources[index].get('origin', '')}:{sources[index].get('name', '')}"
