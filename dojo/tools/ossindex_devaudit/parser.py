import json

from dojo.models import Finding


class OssIndexDevauditParser(object):
    def __init__(self, json_file, test):

        tree = self.parse_json(json_file)

        if tree:
            self.items = [data for data in self.get_items(tree, test)]
        else:
            self.items = []

    def parse_json(self, json_file):
        if json_file is None:
            self.items = []
            return
        try:
            tree = json.load(json_file)
        except:
            raise Exception("Invalid format")

        return tree

    def get_items(self, tree, test):

        items = {}

        results = {key: value for (key, value) in tree.items()}
        for package in results['Packages']:
            package_data = package['Package']
            if len(package['Vulnerabilities']) > 0:
                for vulnerability in package['Vulnerabilities']:
                    item = get_item(
                        dependency_name=package_data['name'],
                        dependency_version=package_data['version'],
                        dependency_source=package_data['pm'],
                        vulnerability=vulnerability,
                        test=test
                    )
                    unique_key = vulnerability['id']
                    items[unique_key] = item

        return items.values()


def get_item(dependency_name, dependency_version, dependency_source, vulnerability, test):

    cwe_data = vulnerability.get('cwe', '')

    if cwe_data == '' or cwe_data is None:
        cwe_text = ''
        cwe = 1035
    else:
        cwe_text = cwe_data
        cwe = cwe_data.replace('CWE-', '')

    finding = Finding(title=dependency_source + ":" + dependency_name + " - " + "(" + dependency_version + ", " + cwe_text + ")",
                      test=test,
                      severity=get_severity(vulnerability['cvssScore']),
                      description=vulnerability['title'],
                      cwe=cwe,
                      cvssv3=vulnerability['cvssVector'].replace('CVSS:3.0', ''),
                      mitigation='Upgrade the component to the latest non-vulnerable version, or remove the package if it is not in use.',
                      references=vulnerability.get('reference', ''),
                      active=False,
                      verified=False,
                      false_p=False,
                      duplicate=False,
                      out_of_scope=False,
                      mitigated=None,
                      static_finding=False,
                      dynamic_finding=False,
                      impact="No impact provided by scan")

    return finding


def get_severity(cvss_score):

    result = 'Unknown'

    if cvss_score != "":
        ratings = [
            ('Critical', 9.0, 10.0),
            ('High', 7.0, 8.9),
            ('Medium', 4.0, 6.9),
            ('Low', 0.1, 3.9)
        ]

        for severity, low, high in ratings:
            if low <= float(cvss_score) <= high:
                result = severity

    return result
