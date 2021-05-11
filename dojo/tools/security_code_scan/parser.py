import re


from dojo.models import Finding

class SecurityCodeScanParser(object):


    def get_scan_types(self):
        return ["Security Code Scan Report"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import Security Code Scan output (--cwe)"

    def convert_severity(self, severity):
        if severity == 'error':
            return 'Critical'
        elif severity == 'warning':
            return 'Medium'
        elif severity == 'low':
            return 'Low'
        else:
            return 'Info'

    def get_findings(self, filename, test):
        dupes = dict()
        finding_regexp = re.compile(r".*Found: (?P<source_file>.*)\((?P<source_line>\d+),(\d+)\): (?P<finding_severity>\w+) (?P<finding_error>.*): CWE-(?P<finding_cwe>\d+): (?P<finding_short_text>.*).*", re.DOTALL)

        for line in filename:
            m = finding_regexp.match(str(line))
            if m is not None:
                finding = Finding(
                    test=test,
                    title=m.group('finding_short_text'),
                    severity=self.convert_severity(m.group('finding_severity')),
                    description=m.group('finding_error') + '-' + m.group('finding_short_text'),
                    file_path=m.group('source_file'),
                    line=m.group('source_line'),
                    sast_source_line=m.group('source_line'),
                    sast_source_file_path=m.group('source_file'),
                    static_finding=True,
                    dynamic_finding=False,
                    nb_occurences=1,
                )
                dupe_key = finding.file_path + str(finding.line) + str(finding.severity)

                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    find.nb_occurences += 1
                else:
                    dupes[dupe_key] = finding

        return list(dupes.values())

