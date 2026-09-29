import json

from dojo.models import Finding


class StaticcheckParser:

    """
    Parser for Staticcheck, the Go static analysis suite.

    ``staticcheck -f json`` writes one JSON object per line rather than a single document.
    Every object is a diagnostic carrying a check code, a message and a source location.
    """

    # Staticcheck has no severity scale. Its JSON carries a "severity" key, but in practice
    # every reported diagnostic is "error"; the field distinguishes reported problems from
    # ones silenced by a //lint:ignore directive, not important ones from unimportant ones.
    # The real signal is which of Staticcheck's four analysers raised the diagnostic, which is
    # encoded in the check code prefix and documented at https://staticcheck.dev/docs/checks/.
    SEVERITY_BY_PREFIX = {
        "SA": "Medium",  # staticcheck: correctness problems and outright bugs
        "S1": "Info",    # gosimple: code that could be written more simply
        "ST1": "Info",   # stylecheck: style and naming
        "QF1": "Info",   # quickfix: refactorings, offered rather than advised
        "U1": "Low",     # unused: unreachable or unused identifiers
    }
    DEFAULT_SEVERITY = "Low"

    # "ignored" appears only with -show-ignored, and means a //lint:ignore silenced it.
    IGNORED_SEVERITY_STATE = "ignored"

    def get_scan_types(self):
        return ["Staticcheck Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Staticcheck reports in JSON format, generated with 'staticcheck -f json ./...'."

    def get_findings(self, file, test):
        content = file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")

        findings = []
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            findings.append(self._to_finding(json.loads(line), test))
        return findings

    def _severity_for(self, code, reported_severity):
        if reported_severity == self.IGNORED_SEVERITY_STATE:
            return "Info"
        # Longest prefix wins, so ST1000 is style rather than an "S1" simplification.
        for prefix in sorted(self.SEVERITY_BY_PREFIX, key=len, reverse=True):
            if code.startswith(prefix):
                return self.SEVERITY_BY_PREFIX[prefix]
        return self.DEFAULT_SEVERITY

    def _to_finding(self, diagnostic, test):
        code = diagnostic.get("code", "")
        message = diagnostic.get("message", "")
        location = diagnostic.get("location") or {}
        end = diagnostic.get("end") or {}
        file_path = location.get("file") or None
        line = location.get("line") or None

        description = [message] if message else []
        description.append(f"**Check:** {code}")
        if location.get("column"):
            description.append(f"**Column:** {location['column']}")
        if end.get("line"):
            end_position = f"{end['line']}"
            if end.get("column"):
                end_position += f":{end['column']}"
            description.append(f"**Ends at:** {end_position}")
        if diagnostic.get("severity"):
            description.append(f"**Reported state:** {diagnostic['severity']}")

        # A staticcheck "compile" record is a build failure, not a lint result: the code did not
        # compile, so the package was never analysed. Surfaced as High because the scan is blind.
        is_compile_error = code == "compile"

        return Finding(
            title=f"{code}: {message}" if code else message,
            test=test,
            description="\n".join(description),
            severity="High" if is_compile_error else self._severity_for(code, diagnostic.get("severity")),
            file_path=file_path,
            line=line,
            vuln_id_from_tool=code or None,
            active=diagnostic.get("severity") != self.IGNORED_SEVERITY_STATE,
            false_p=diagnostic.get("severity") == self.IGNORED_SEVERITY_STATE,
            static_finding=True,
            dynamic_finding=False,
        )
