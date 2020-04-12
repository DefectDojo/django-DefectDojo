__author__ = 'feeltheajf'

from dateutil import parser
import json
from dojo.models import Finding


class BrakemanScanParser(object):
    def __init__(self, filename, test):
        tree = filename.read()
        try:
            data = json.loads(str(tree, 'utf-8'))
        except:
            data = json.loads(tree)
        dupes = dict()
        find_date = parser.parse(data['scan_info']['end_time'])

        for item in data['warnings']:
            categories = ''
            language = ''
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
            if item['code'] is not null:
                findingdetail += 'Code:\n' + item['code'] + '\n'
            if item['render_path'] is not null:
                findingdetail += 'Render path:\n'
                findingdetail += "User input coming from \"{}\" might be used for {} in {}:{} ({}:{})".format(item['user_input'], item['warning_type'], item['render_path']['class'], item['render_path']['method'], item['render_path']['file'], item['render_path']['line'])
            sev = 'Medium'
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
                    impact=impact,
                    references=references,
                    file_path=item['file'],
                    line=item['line'],
                    date=find_date,
                    static_finding=True)

                dupes[dupe_key] = find

        self.items = list(dupes.values())
