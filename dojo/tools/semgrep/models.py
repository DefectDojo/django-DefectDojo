from dojo.tools.semgrep.helpers import (format_code,
                                        format_linenums,
                                        format_message,
                                        format_metavars)


class SemgrepJSONResult:
    def __init__(self, path='', start={}, end={}, extra={}):
        self.path = path
        self.start = format_linenums(start)
        self.end = format_linenums(end)

        self.severity = "Info"
        self.cwe = 42
        self.message = "Detected by semgrep rule"
        self.fix = "None"
        self.lines = "None"
        self.references = "Detected by semgrep rule"
        self.test = "SemGrep rule"

        if not extra:
            return

        metadata, metavars = extra.get('metadata'), extra.get('metavars')
        self.fix = format_code(extra.get('fix'))
        self.lines = format_code(extra.get('lines'))
        self.message = format_message(extra.get('message'))

        if not metadata:
            return

        self.cwe = metadata.get('cwe')
        self.owasp = metadata.get('owasp')

        # Convert Semgrep severity to defectDojo Severity
        semSeverity = metadata.get('severity')

        if semSeverity == "WARNING":
            self.severity = "Low"

        if semSeverity == "ERROR":
            self.severity = "High"

        self.references = format_message(metadata.get('message'))
        self.source_rule_url = metadata.get('source-rule-url')

        if not metavars:
            return

        self.metavars = format_metavars(extra.get('metavars'))
