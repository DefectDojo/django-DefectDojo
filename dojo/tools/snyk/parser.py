import json

from dojo.models import Finding


class SnykParser(object):
    def __init__(self, json_output, test):

        tree = self.parse_json(json_output)

        if tree:
            self.items = [data for data in self.get_items(tree, test)]
        else:
            self.items = []

    def parse_json(self, json_output):
        try:
            data = json_output.read()
            try:
                tree = json.loads(str(data, 'utf-8'))
            except:
                tree = json.loads(data)
        except:
            raise Exception("Invalid format")

        return tree

    def get_items(self, tree, test):
        items = {}
        if 'vulnerabilities' in tree:
            vulnerabilityTree = tree['vulnerabilities']

            for node in vulnerabilityTree:

                item = get_item(node, test)
                unique_key = node['title'] + str(node['packageName'] + str(
                    node['version']) + str(node['from']))
                items[unique_key] = item

        return list(items.values())


def get_item(vulnerability, test):

    cve_references = ''
    cwe_references = ''

    # vulnerable and unaffected versions can be in string format for a single vulnerable version, or an array for multiple versions depending on the language.
    if isinstance(vulnerability['semver']['vulnerable'], list):
        vulnerable_versions = ", ".join(vulnerability['semver']['vulnerable'])
    else:
        vulnerable_versions = vulnerability['semver']['vulnerable']

    if 'identifiers' in vulnerability:
        if 'CVE' in vulnerability['identifiers']:
            if isinstance(vulnerability['identifiers']['CVE'], list):
                # Per the current json format, if several CVEs listed, take the first one.
                cve = ' '.join(vulnerability['identifiers']['CVE']).split(" ")[0]
                if len(vulnerability['identifiers']['CVE']) > 1:
                    cve_references = ', '.join(vulnerability['identifiers']['CVE'])
            else:
                # In case the structure is not a list?
                cve = vulnerability['identifiers']['CVE']

        if 'CWE' in vulnerability['identifiers']:
            if isinstance(vulnerability['identifiers']['CWE'], list):
                # Per the current json format, if several CWEs, take the first one.
                cwe = ' '.join(vulnerability['identifiers']['CWE']).split(" ")[0].split("-")[1]
                if len(vulnerability['identifiers']['CVE']) > 1:
                    cwe_references = ', '.join(vulnerability['identifiers']['CWE'])
            else:
                # in case the structure is not a list?
                cwe = ''.join(vulnerability['identifiers']['CWE']).split("-")[1]
    else:
        # If no identifiers, set to defaults
        cve = None
        cwe = 1035

    # Following the CVSS Scoring per https://nvd.nist.gov/vuln-metrics/cvss
    if 'cvssScore' in vulnerability:
        # If we're dealing with a license finding, there will be no cvssScore
        if vulnerability['cvssScore'] <= 3.9:
            severity = "Low"
        elif vulnerability['cvssScore'] > 4.0 and vulnerability['cvssScore'] <= 6.9:
            severity = "Medium"
        elif vulnerability['cvssScore'] > 7.0 and vulnerability['cvssScore'] <= 8.9:
            severity = "High"
        else:
            severity = "Critical"
    else:
        # Re-assign 'severity' directly
        severity = vulnerability['severity'].title()

    if 'id' in vulnerability:
        references = "Custom SNYK ID: {}\n\n".format(vulnerability['id'])

    if cve_references or cwe_references:
        references += "Several CVEs or CWEs were reported: \n\n{}\n{}".format(
            cve_references, cwe_references)
    else:
        references += "Refer to the description above for references."

    # create the finding object
    finding = Finding(
        title=vulnerability['from'][0] + ": " + vulnerability['title'],
        test=test,
        severity=severity,
        cwe=cwe,
        cve=cve,
        description="<h2>Details</h2><p><li>Vulnerable Package: " +
        vulnerability['packageName'] + "</li><li> Current Version: " + str(
            vulnerability['version']) + "</li><li>Vulnerable Version(s): " +
        vulnerable_versions + "</li><li>Vulnerable Path: " + " > ".join(
            vulnerability['from']) + "</li></p>" + vulnerability['description'],
        mitigation="A fix (if available) will be provided in the description.",
        references=references,
        component_name=vulnerability['packageName'],
        component_version=vulnerability['version'],
        active=False,
        verified=False,
        false_p=False,
        duplicate=False,
        out_of_scope=False,
        mitigated=None,
        impact=severity)

    finding.description = finding.description.strip()

    return finding
