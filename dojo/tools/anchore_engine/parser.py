import json

from dojo.models import Finding


class AnchoreEngineParser(object):
    def get_scan_types(self):
        return ["Anchore Engine Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Anchore Engine Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Anchore-CLI JSON vulnerability report format."

    def get_findings(self, filename, test):
        data = json.load(filename)
        dupes = dict()
        for item in data['vulnerabilities']:
            cve = item.get('vuln')

            title = item['vuln'] + ' - ' + item['package'] + '(' + item['package_type'] + ')'

            # Finding details information
            # depending on version image_digest/imageDigest
            findingdetail = '**Image hash**: ' + item.get('image_digest', item.get('imageDigest', 'None')) + '\n\n'
            findingdetail += '**Package**: ' + item['package'] + '\n\n'
            findingdetail += '**Package path**: ' + item['package_path'] + '\n\n'
            findingdetail += '**Package type**: ' + item['package_type'] + '\n\n'
            findingdetail += '**Feed**: ' + item['feed'] + '/' + item['feed_group'] + '\n\n'
            findingdetail += '**CVE**: ' + cve + '\n\n'
            findingdetail += '**CPE**: ' + item['package_cpe'] + '\n\n'

            sev = item['severity']
            if sev == "Negligible" or sev == "Unknown":
                sev = 'Info'

            mitigation = "Upgrade to " + item['package_name'] + ' ' + item['fix'] + '\n'
            mitigation += "URL: " + item['url'] + '\n'

            references = item['url']

            dupe_key = '|'.join([
                item.get('image_digest', item.get('imageDigest', 'None')),  # depending on version image_digest/imageDigest
                item['feed'],
                item['feed_group'],
                item['package_name'],
                item['package_version'],
                item['package_path'],
                item['vuln']
            ])

            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                dupes[dupe_key] = True

                find = Finding(
                    title=title,
                    test=test,
                    cve=cve,
                    description=findingdetail,
                    severity=sev,
                    numerical_severity=Finding.get_numerical_severity(sev),
                    mitigation=mitigation,
                    impact='No impact provided',
                    references=references,
                    file_path=item["package_path"],
                    component_name=item['package_name'],
                    component_version=item['package_version'],
                    url=item.get('url'),
                    static_finding=True,
                    dynamic_finding=False)

                dupes[dupe_key] = find

        return list(dupes.values())
