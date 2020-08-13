from helpers import (create_dedupe_key,
                     format_code, 
                     format_linenums,
                     format_message,
                     format_metavars,
                     format_references)

class SemgrepJSONResult:

    def __init__(self, check_id='', path='', start={}, end={}, extra={}):
        self.check_id = check_id
        self.path = path
        self.start = format_linenums(start)
        self.end = format_linenums(end)
        self.dedupe_key = create_dedupe_key(
            self.check_id,
            self.path,
            self.start,
            self.end
        )

        if not extra:
            return

        metadata, metavars = extra.get('metadata'), extra.get('metavars')

        self.fix = format_code(extra.get('fix'))
        self.lines = format_code(extra.get('lines'))
        self.message = format_message(extra.get('message'))
        self.severity = extra.get('severity')

        if not metadata:
            return

        self.cwe = metadata.get('cwe')
        self.owasp = metadata.get('owasp')
        self.references = format_message(metadata.get('message'))
        self.source_rule_url = metadata.get('source-rule-url')

        if not metavars:
            return

        self.metavars = format_metavars(extra.get('metavars'))
