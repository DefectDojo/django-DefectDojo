import json
from datetime import datetime
from dojo.models import Finding


class AwsSecurityHubParser(object):

    def get_scan_types(self):
        return ["AWS Security Hub Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "AWS Security Hub Scan"

    def get_description_for_scan_types(self, scan_type):
        return "AWS Security Hub exports in JSON format."

    def get_findings(self, filehandle, test):
        tree = json.load(filehandle)
        return self.get_items(tree, test)

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
    finding_id = finding.get('Id', "")
    title = finding.get('Title', "")
    severity = finding.get('Severity', {}).get('Label', 'INFORMATIONAL').title()
    description = finding.get('Description', "")
    resources = finding.get('Resources', "")
    resource_id = resources[0]['Id'].split(':')[-1]
    mitigation = finding.get('Remediation', {}).get('Recommendation', {}).get('Text', "")
    references = finding.get('Remediation', {}).get('Recommendation', {}).get('Url')
    false_p = False

    if finding.get('Compliance', {}).get('Status', "PASSED") == 'PASSED':
        is_Mitigated = True
        active = False
        if finding.get('LastObservedAt', None):
            try:
                mitigated = datetime.strptime(finding.get('LastObservedAt'), "%Y-%m-%dT%H:%M:%S.%fZ")
            except:
                mitigated = datetime.strptime(finding.get('LastObservedAt'), "%Y-%m-%dT%H:%M:%fZ")
        else:
            mitigated = datetime.utcnow()
    else:
        mitigated = None
        is_Mitigated = False
        active = True

    finding = Finding(title=f"Resource: {resource_id} - {title}",
                      test=test,
                      description=description,
                      mitigation=mitigation,
                      references=references,
                      severity=severity,
                      active=active,
                      verified=False,
                      false_p=false_p,
                      unique_id_from_tool=finding_id,
                      mitigated=mitigated,
                      is_mitigated=is_Mitigated,
                      )

    return finding
