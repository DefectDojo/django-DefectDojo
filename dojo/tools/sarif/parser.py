import logging
import json
from datetime import datetime
from dojo.models import Finding

logger = logging.getLogger(__name__)


class SarifParser(object):
    """
        This class parse Acunetix XML file using helper methods from 'parser_helper.py'.
    """
    def __init__(self, filehandle, test):
        tree = self.parse_json(filehandle)

        # by default give the test a title linked to the first tool in the report
        test.title = f"SARIF ({tree['runs'][0]['tool']['driver']['name']})"

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
        items = list()
        # for each runs
        for run in tree.get('runs', list()):
            # load rules
            rules = get_rules(run)
            artifacts = get_artifacts(run)
            for result in run.get('results', list()):
                item = get_item(result, rules, artifacts, test)
                items.append(item)
        return items


def get_rules(run):
    rules = {}
    for item in run['tool']['driver'].get('rules', []):
        rules[item['id']] = item
    return rules


def get_rule_tags(rule):
    if not 'properties' in rule:
        return []
    if not 'tags' in rule['properties']:
        return []
    else:
        return rule['properties']['tags']


def get_rule_cwes(rule):



def get_artifacts(run):
    artifacts = {}
    custom_index = 0  # hack because some tool doesn't generate this attribute
    for tree_artifact in run.get('artifacts', []):
        artifacts[tree_artifact.get('index', custom_index)] = tree_artifact
        custom_index += 1
    return artifacts


def get_severity(data):
    """Convert level value to severity
    """
    if "warning" == data:
        return 'Medium'
    elif "error" == data:
        return 'Critical'
    else:
        return 'Info'


def get_message(data):
    # TODO manage markdown
    return data['text']


def get_item(finding, rules, artifacts, test):
    mitigation = finding.get('Remediation', {}).get('Recommendation', {}).get('Text', "")
    references = finding.get('Remediation', {}).get('Recommendation', {}).get('Url')
    verified = False
    false_p = False
    duplicate = False
    out_of_scope = False
    impact = None

    if finding.get('Compliance', {}).get('Status', "PASSED"):
        if finding.get('LastObservedAt', None):
            try:
                mitigated = datetime.strptime(finding.get('LastObservedAt'), "%Y-%m-%dT%H:%M:%S.%fZ")
            except:
                mitigated = datetime.strptime(finding.get('LastObservedAt'), "%Y-%m-%dT%H:%M:%fZ")
        else:
            mitigated = datetime.utcnow()
    else:
        mitigated = None

    # if there is a location get it
    file_path = None
    line = -1
    if "locations" in finding:
        location = finding['locations'][0]
        file_path = location['physicalLocation']['artifactLocation']['uri']
        # 'region' attribute is optionnal
        if 'region' in location['physicalLocation']:
            line = location['physicalLocation']['region']['startLine']

    # test rule link
    rule = rules[finding['ruleId']]
    # get the severity from the rule
    if 'defaultConfiguration' in rule:
        severity = get_severity(rule['defaultConfiguration'].get('level', 'warning'))
    else:
        severity = get_severity('warning')

    if 'shortDescription' in rule:
        title = get_message(rule['shortDescription'])
        description = get_message(rule['shortDescription'])
    else:
        title = finding['message'].get('text', 'No text')
        description = get_message(rule['fullDescription'])

    # we add a special 'None' case if there is no CWE
    cwes = [None]
    if rule is not None:
        cwes_extracted = get_rule_cwes(rule)
        if len(cwes_extracted) > 1:
            cwes = cwes_extracted

    for cwe in cwes:
        finding = Finding(title=finding['ruleId'],
                        test=test,
                        severity=severity,
                        numerical_severity=Finding.get_numerical_severity(severity),
                        description=description,
                        mitigation=mitigation,
                        references=references,
                        cve=None,  # for now CVE are not managed or it's not very clear how in the spec
                        cwe=cwe,
                        active=True,
                        verified=verified,
                        false_p=false_p,
                        duplicate=duplicate,
                        out_of_scope=out_of_scope,
                        mitigated=mitigated,
                        impact="No impact provided",
                        static_finding=True,  # by definition
                        dynamic_finding=False,  # by definition
                        file_path=file_path,
                        line=line)

    return finding
