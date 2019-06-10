__author__ = 'feeltheajf'

from dateutil import parser
import json
from dojo.models import Finding


class BrakemanScanParser(object):
    def __init__(self, filename, test):
        data = json.load(filename)
        dupes = dict()
        find_date = parser.parse(data['scan_info']['end_time'])

        for item in data['warnings']:
            categories = ''
            language = ''
            mitigation = ''
            impact = ''
            references = ''
            findingdetail = ''
            title = ''
            group = ''
            status = ''

            title = item['warning_type'] + '. ' + item['message']

            # Finding details information
            findingdetail += 'Filename: ' + item['file'] + '\n'
            findingdetail += 'Line number: ' + str(item['line'] or '') + '\n'
            findingdetail += 'Issue Confidence: ' + item['confidence'] + '\n\n'
            findingdetail += 'Code:\n'
            findingdetail += item['code'] or '' + '\n'

            sev = 'Medium'
            mitigation = 'coming soon'
            references = item['link']

            dupe_key = item['fingerprint']

            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                dupes[dupe_key] = True

                find = Finding(
                    title=title,
                    test=test,
                    active=False,
                    verified=False,
                    description=findingdetail,
                    severity=sev,
                    numerical_severity=Finding.get_numerical_severity(sev),
                    mitigation=mitigation,
                    impact=impact,
                    references=references,
                    file_path=item['file'],
                    line=item['line'],
                    url='N/A',
                    date=find_date,
                    static_finding=True)

                dupes[dupe_key] = find

        self.items = list(dupes.values())
