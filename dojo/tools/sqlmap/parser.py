import csv
import io
import re

from dojo.models import Endpoint, Finding

# sqlmap only reports an injection point after it has confirmed the injection works, so this is not a
# pattern match that might be wrong. Confirmed SQL injection is commonly triaged up to Critical
# depending on what the affected data is worth, which is a question about the application rather than
# something sqlmap measures.
DEFAULT_SEVERITY = "High"
SQL_INJECTION_CWE = 89

# The header sqlmap writes to its CSV results file, used to tell the two artifacts apart.
CSV_HEADER = "Target URL,Place,Parameter,Technique(s)"

# sqlmap writes the CSV technique column as the FIRST LETTER of each technique name, uppercased
# (lib/controller/controller.py: "".join(techniques[_][0].upper() for _ in sorted(value))). Note that
# an inline query is "I" here, while the --technique command-line flag spells the same technique "Q".
CSV_TECHNIQUE_LETTERS = {
    "B": "boolean-based blind",
    "E": "error-based",
    "I": "inline query",
    "S": "stacked queries",
    "T": "time-based blind",
    "U": "UNION query",
}

# A block in the log file opens with the parameter and where it was found:
#   Parameter: id (GET)
LOG_PARAMETER = re.compile(r"^Parameter:\s*(?P<parameter>.+?)\s*\((?P<place>[^)]+)\)\s*$")
LOG_FIELD = re.compile(r"^\s*(?P<field>Type|Title|Payload):\s*(?P<value>.*)$")
LOG_DBMS = re.compile(r"^back-end DBMS:\s*(?P<dbms>.+?)\s*$")


class SqlmapParser:

    """Parses the report sqlmap writes for a target: either its log file or its CSV results file."""

    def get_scan_types(self):
        return ["Sqlmap Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Sqlmap Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a sqlmap report: either the per-target log file written under the output "
            "directory, or the CSV results file. Both are accepted."
        )

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        # A clean sqlmap run writes an EMPTY log file and a header-only CSV, so a report with nothing
        # in it is the ordinary result of finding no injection and must not raise.
        if not content.strip():
            return []
        if content.lstrip().startswith(CSV_HEADER):
            return self.parse_csv(content, test)
        return self.parse_log(content, test)

    def parse_csv(self, content, test):
        """Parse the CSV results file, which is the only sqlmap artifact carrying the target URL."""
        findings = {}
        for row in csv.DictReader(io.StringIO(content)):
            parameter = (row.get("Parameter") or "").strip()
            if not parameter:
                continue
            url = (row.get("Target URL") or "").strip()
            place = (row.get("Place") or "").strip()
            # sqlmap APPENDS to the results file, so re-running a scan writes the same injection
            # point again. Without this the second run doubles every finding.
            key = (url, place, parameter)
            if key in findings:
                continue
            techniques = [
                CSV_TECHNIQUE_LETTERS.get(letter, letter)
                for letter in (row.get("Technique(s)") or "").strip()
            ]
            notes = (row.get("Note(s)") or "").strip()
            findings[key] = self.build_finding(
                parameter=parameter,
                place=place,
                url=url,
                lines=self.csv_description(url, place, parameter, techniques, notes),
                test=test,
            )
        return list(findings.values())

    def parse_log(self, content, test):
        """
        Parse the per-target log file, which carries the payload sqlmap confirmed.

        The log has no target URL in it - it is written into a directory named after the host - so a
        finding from a log has no endpoint. The CSV results file is the artifact to import when the
        endpoint matters.
        """
        findings = {}
        parameter = place = None
        techniques = []
        dbms = None

        for raw in content.splitlines():
            line = raw.rstrip()
            if header := LOG_PARAMETER.match(line.strip()):
                parameter = header.group("parameter")
                place = header.group("place")
                techniques = []
                # sqlmap APPENDS to the log, so a resumed run writes the same injection point a
                # second time ("resumed the following injection point(s) from stored session").
                # Keying on place and parameter keeps that one finding.
                key = (place, parameter)
                if key not in findings:
                    findings[key] = techniques
                else:
                    techniques = findings[key]
                continue
            if match := LOG_DBMS.match(line.strip()):
                dbms = match.group("dbms")
                continue
            if parameter and (field := LOG_FIELD.match(line)):
                name = field.group("field").lower()
                value = field.group("value").strip()
                if name == "type":
                    techniques.append({"type": value})
                elif techniques:
                    techniques[-1][name] = value

        return [
            self.build_finding(
                parameter=parameter,
                place=place,
                url=None,
                lines=self.log_description(place, parameter, entries, dbms),
                test=test,
            )
            for (place, parameter), entries in findings.items()
        ]

    def build_finding(self, parameter, place, url, lines, test):
        finding = Finding(
            test=test,
            title=f"SQL injection in {place} parameter '{parameter}'",
            severity=DEFAULT_SEVERITY,
            cwe=SQL_INJECTION_CWE,
            description="\n".join(lines),
            mitigation=(
                "Pass the parameter to the database as a bound value instead of building the "
                "statement by concatenating it into SQL."
            ),
            static_finding=False,
            # sqlmap confirms the injection against a running application.
            dynamic_finding=True,
        )
        if url:
            finding.unsaved_endpoints = [Endpoint.from_uri(url)]
        return finding

    def csv_description(self, url, place, parameter, techniques, notes):
        lines = []
        if url:
            lines.append(f"**Target:** {url}")
        lines.append(f"**Parameter:** {parameter} ({place})")
        if techniques:
            lines.append(f"**Techniques:** {', '.join(techniques)}")
        if notes:
            lines.append(f"**Notes:** {notes}")
        # The CSV records which techniques worked but not the payload that proved it, so say where the
        # payload is rather than leaving a reader to wonder why it is missing.
        lines.append(
            "**Note:** the CSV results file records the techniques but not the payloads; those are "
            "in the per-target log file.",
        )
        return lines

    def log_description(self, place, parameter, entries, dbms):
        lines = [f"**Parameter:** {parameter} ({place})"]
        if dbms:
            lines.append(f"**Back-end DBMS:** {dbms}")
        for entry in entries:
            lines.extend(["", f"**Type:** {entry.get('type', '')}"])
            if title := entry.get("title"):
                lines.append(f"**Title:** {title}")
            if payload := entry.get("payload"):
                # The payload is the evidence a triager needs, so it is kept verbatim.
                lines.append(f"**Payload:** `{payload}`")
        return lines
