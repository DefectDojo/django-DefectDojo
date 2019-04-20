__author__ = 'jaguasch'

import json
from dojo.models import Finding
from datetime import datetime


class AnchoreEngineScanParser(object):
    def __init__(self, filename, test):
        data = json.load(filename)
        dupes = dict()
        find_date = datetime.now()

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

            title = item['vuln'] + ' - ' + item['package'] + '(' + item['package_type'] + ')'

            # Finding details information
            findingdetail += 'Image hash: ' + data['imageDigest'] + '\n'
            findingdetail += 'Package: ' + item['package'] + '\n'
            findingdetail += 'Package path: ' + item['package_path'] + '\n'
            findingdetail += 'Package type: ' + item['package_type'] + '\n'
            findingdetail += 'Feed: ' + item['feed'] + '/' + item['feed_group'] + '\n'
            findingdetail += 'CVE: ' + item['vuln'] + '\n'
            findingdetail += 'CPE: ' + item['package_cpe'] + '\n'

            sev = item['severity']
            if sev == "Negligible" or sev == "Unknown":
                sev = u'Info'

            mitigation += "Upgrade to " + item['package_name'] + ' ' + item['fix'] + '\n'
            mitigation += "URL: " + item['url'] + '\n'

            references = item['url']

            dupe_key = data['imageDigest'] + "|" + item['feed'] + "|" + item['feed_group'] + "|" + item['package'] + '|' + item['vuln']

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
                    file_path=item["package_path"],
                    url=item['url'],
                    date=find_date,
                    static_finding=True)

                dupes[dupe_key] = find

        self.items = dupes.values()
