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
            vulnerability_id = item.get('vuln')

            title = item['vuln'] + ' - ' + item['package'] + '(' + item['package_type'] + ')'

            # Finding details information
            # depending on version image_digest/imageDigest
            findingdetail = '**Image hash**: ' + item.get('image_digest', item.get('imageDigest', 'None')) + '\n\n'
            findingdetail += '**Package**: ' + item['package'] + '\n\n'
            findingdetail += '**Package path**: ' + item['package_path'] + '\n\n'
            findingdetail += '**Package type**: ' + item['package_type'] + '\n\n'
            findingdetail += '**Feed**: ' + item['feed'] + '/' + item['feed_group'] + '\n\n'
            findingdetail += '**CPE**: ' + item['package_cpe'] + '\n\n'
            findingdetail += '**Description**: ' + item.get('description', '<None>') + '\n\n'

            sev = item['severity']
            if sev == "Negligible" or sev == "Unknown":
                sev = 'Info'

            mitigation = "Upgrade to " + item['package_name'] + ' ' + item['fix'] + '\n'
            mitigation += "URL: " + item['url'] + '\n'

            cvssv3_base_score = None
            if item['feed'] == 'nvdv2' or item['feed'] == 'vulnerabilities':
                if 'nvd_data' in item and len(item['nvd_data']) > 0:
                    cvssv3_base_score = item['nvd_data'][0]['cvss_v3']['base_score']
            else:
                # there may be other keys, but taking a best guess here
                if 'vendor_data' in item and len(item['vendor_data']) > 0:
                    # sometimes cvssv3 in 1st element will have -1 for "not set", but have data in the 2nd array item
                    if 'cvss_v3' in item['vendor_data'][0] and item['vendor_data'][0]['cvss_v3']['base_score'] != -1:
                        cvssv3_base_score = item['vendor_data'][0]['cvss_v3']['base_score']
                    elif len(item['vendor_data']) > 1:
                        if 'cvss_v3' in item['vendor_data'][1] and item['vendor_data'][1]['cvss_v3']['base_score'] != -1:
                            cvssv3_base_score = item['vendor_data'][1]['cvss_v3']['base_score']

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
                    cvssv3_score=cvssv3_base_score,
                    description=findingdetail,
                    severity=sev,
                    mitigation=mitigation,
                    references=references,
                    file_path=item["package_path"],
                    component_name=item['package_name'],
                    component_version=item['package_version'],
                    url=item.get('url'),
                    static_finding=True,
                    dynamic_finding=False,
                    vuln_id_from_tool=item.get('vuln'),
                )
                if vulnerability_id:
                    find.unsaved_vulnerability_ids = [vulnerability_id]
                dupes[dupe_key] = find

        return list(dupes.values())
