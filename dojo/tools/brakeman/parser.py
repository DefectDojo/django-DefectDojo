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
            impact = ''
            references = ''
            findingdetail = ''
            title = ''

            title = item['warning_type'] + '. ' + item['message']

            # Finding details information
            findingdetail += 'Filename: ' + item['file'] + '\n'
            if item['line'] is not None:
                findingdetail += 'Line number: ' + str(item['line']) + '\n'
            findingdetail += 'Issue Confidence: ' + item['confidence'] + '\n\n'
            if item['code'] is not None:
                findingdetail += 'Code:\n' + item['code'] + '\n'
            if item['user_input'] is not None:
                findingdetail += 'User input:\n' + item['user_input'] + '\n'
            if item['render_path'] is not None:
                findingdetail += 'Render path details:\n'
                findingdetail += json.dumps(item['render_path'], indent=4)
                #for render_path in item['render_path']:
                #    findingdetail += "User input coming from \"{}\" might be used for {} in {}:{} ({}:{})\n".format(item['user_input'], item['warning_type'], render_path['class'], render_path['method'], render_path['file'], str(render_path['line']))
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
