import json

from dojo.models import Finding


class AnchoreCTLVulnsParser(object):
    def get_scan_types(self):
        return ["AnchoreCTL Vuln Report"]

    def get_label_for_scan_types(self, scan_type):
        return "AnchoreCTL Vuln Report"

    def get_description_for_scan_types(self, scan_type):
        return "AnchoreCTLs JSON vulnerability report format."

    def get_findings(self, filename, test):
        data = json.load(filename)
        dupes = dict()
        for item in data:
            vulnerability_id = item.get('vuln')

            title = item['vuln'] + ' - ' + item['package'] + '(' + item['packageType'] + ')'

            # Finding details information
            # depending on version image_digest/imageDigest
            findingdetail = '**Image hash**: ' + item.get('imageDigest', 'None') + '\n\n'
            findingdetail += '**Package**: ' + item['package'] + '\n\n'
            findingdetail += '**Package path**: ' + item['packagePath'] + '\n\n'
            findingdetail += '**Package type**: ' + item['packageType'] + '\n\n'
            findingdetail += '**Feed**: ' + item['feed'] + '/' + item['feedGroup'] + '\n\n'
            findingdetail += '**CPE**: ' + item['packageCpe'] + '\n\n'
            findingdetail += '**Description**: ' + item.get('description', '<None>') + '\n\n'

            sev = item['severity']
            if sev == "Negligible" or sev == "Unknown":
                sev = 'Info'

            mitigation = "Upgrade to " + item['packageName'] + ' ' + item['fix'] + '\n'
            mitigation += "URL: " + item['url'] + '\n'

            cvssv3_base_score = None
            if item['feed'] == 'nvdv2' or item['feed'] == 'vulnerabilities':
                if 'nvdData' in item and len(item['nvdData']) > 0:
                    cvssv3_base_score = item['nvdData'][0]['cvssV3']['baseScore']
            else:
                # there may be other keys, but taking a best guess here
                if 'vendorData' in item and len(item['vendorData']) > 0:
                    # sometimes cvssv3 in 1st element will have -1 for "not set", but have data in the 2nd array item
                    if 'cvssV3' in item['vendorData'][0] and item['vendorData'][0]['cvssV3']['baseScore'] != -1:
                        cvssv3_base_score = item['vendorData'][0]['cvssV3']['baseScore']
                    elif len(item['vendorData']) > 1:
                        if 'cvssV3' in item['vendorData'][1] and item['vendorData'][1]['cvssV3']['baseScore'] != -1:
                            cvssv3_base_score = item['vendorData'][1]['cvssV3']['baseScore']

            references = item['url']

            dupe_key = '|'.join([
                item.get('imageDigest', 'None'),  # depending on version image_digest/imageDigest
                item['feed'],
                item['feedGroup'],
                item['packageName'],
                item['packageVersion'],
                item['packagePath'],
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
                    file_path=item["packagePath"],
                    component_name=item['packageName'],
                    component_version=item['packageVersion'],
                    url=item.get('url'),
                    static_finding=True,
                    dynamic_finding=False,
                    vuln_id_from_tool=item.get('vuln'),
                )
                if vulnerability_id:
                    find.unsaved_vulnerability_ids = [vulnerability_id]
                dupes[dupe_key] = find

        return list(dupes.values())
