from dojo.tools.semgrep.helpers import (create_dedupe_key,
                                        format_code,
                                        format_linenums,
                                        format_message,
                                        format_metavars)

class SemgrepJSONResult:

    def __init__(self, extra=None, path='', start=None, end=None):
        self.path = path

        self.start = 0
        self.end = 0
        self.severity = "Info"
        self.title = "SemGrep detection rule"
        self.message = "Detected by semgrep rule"
        self.fix = "None"
        self.lines = "None"
        self.references = "Detected by semgrep rule"
        self.test = "SemGrep rule"
        self.description = "Detected by semgrep rules"
        self.cwe = 0


        if start is not None:
            self.start = start['line']
        if end is not None:
            self.end = end['line']

        if extra is None:
            return

        metadata, metavars = extra.get('metadata'), extra.get('metavars')
        self.fix = format_code(extra.get('fix'))
        self.lines = format_code(extra.get('lines'))
        self.message = format_message(extra.get('message'))

        if not metadata:
            return

        #parse CWE
        self.title = metadata.get("cwe").partition(':')[2]
        self.cwe = metadata.get("cwe").partition(':')[0].partition('-')[2]
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
