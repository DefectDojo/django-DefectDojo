from dojo.models import Finding
from datetime import datetime
import json


class AwsSecurityFindingFormatParser:
    def __init__(self, filehandle, test):
        tree = self.parse_json(filehandle)

        if tree:
            self.items = [data for data in self.get_items(tree, test)]
        else:
            self.items = []

    def parse_json(self, filehandle):
        try:
            data = filehandle.read()
        except:
            return None

        try:
            tree = json.loads(data)
        except:
            raise Exception("Invalid format")

        return tree

    def get_items(self, tree, test):
        items = {}
        # DefectDojo/django-DefectDojo/issues/2780
        findings = tree.get('Findings', tree.get('findings', None))

        if not findings:
            return list()

        for node in findings:
            item = get_item(node, test)
            key = node['Id']
            items[key] = item

        return list(items.values())


def get_item(finding, test):
    title = finding.get('Title', "")
    severity = finding.get('Severity', {}).get('Label', 'INFORMATIONAL').title()
    description = finding.get('Description', "")
    mitigation = finding.get('Remediation', {}).get('Recommendation', {}).get('Text', "")
    references = finding.get('Remediation', {}).get('Recommendation', {}).get('Url')
    cve = None
    cwe = None
    active = True
    verified = False
    false_p = False
    duplicate = False
    out_of_scope = False
    impact = None

    if finding.get('Compliance', {}).get('Status', "PASSED"):
        mitigated = datetime.strptime(
            finding.get('LastObservedAt', datetime.utcnow()),
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
    else:
        mitigated = None

    finding = Finding(title=title,
                      test=test,
                      severity=severity,
                      description=description,
                      mitigation=mitigation,
                      references=references,
                      cve=cve,
                      cwe=cwe,
                      active=active,
                      verified=verified,
                      false_p=false_p,
                      duplicate=duplicate,
                      out_of_scope=out_of_scope,
                      mitigated=mitigated,
                      impact="No impact provided")

    return finding
