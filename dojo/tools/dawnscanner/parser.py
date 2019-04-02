__author__ = 'jaguasch'

from dateutil import parser
import json
import hashlib
from dojo.models import Finding


class DawnScannerParser(object):
    def __init__(self, filename, test):
        data = json.load(filename)

        dupes = dict()
        find_date = parser.parse(data['scan_started'])

        for item in data['vulnerabilities']:
            categories = ''
            language = ''
            mitigation = ''
            impact = ''
            references = ''
            findingdetail = ''
            title = ''
            group = ''
            status = ''

            title = item['name']

            # Finding details information
            findingdetail = item['message'].encode('ascii', 'ignore')
            sev = item['severity'].capitalize()
            mitigation = item['remediation']
            references = item['cve_link']

            dupe_key = hashlib.md5(sev + '|' + title).hexdigest()

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
                    url='N/A',
                    date=find_date,
                    static_finding=True)

                dupes[dupe_key] = find

        self.items = dupes.values()
