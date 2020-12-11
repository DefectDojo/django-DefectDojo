import logging
import json
from datetime import datetime
#from dojo.models import Finding

logger = logging.getLogger(__name__)

class Finding():
    def __init__(self, title, test, severity, numerical_severity,
                 description, mitigation, references, cve, cwe,
                 active, verified, false_p, duplicate, out_of_scope,
                 mitigated, impact, static_finding, dynamic_finding, file_path, line):
        self.title = ""
        self.file_path = file_path
        self.line = line
        self.severity = severity
        self.description = description
        self.static_finding = static_finding
        self.dynamic_finding = dynamic_finding

    @staticmethod
    def get_numerical_severity(severity):
        if severity == 'Critical':
            return 'S0'
        elif severity == 'High':
            return 'S1'
        elif severity == 'Medium':
            return 'S2'
        elif severity == 'Low':
            return 'S3'
        elif severity == 'Info':
            return 'S4'
        else:
            return 'S5'

    @staticmethod
    def get_number_severity(severity):
        if severity == 'Critical':
            return 4
        elif severity == 'High':
            return 3
        elif severity == 'Medium':
            return 2
        elif severity == 'Low':
            return 1
        elif severity == 'Info':
            return 0
        else:
            return 5


class SarifArtifact(object):
    """
    """
    def __init__(self, location):
        self.location = location


class SarifArtifactLocation(object):
    """
    """ 
    def __init__(self, uri, index):
        self.uri = uri
        self.index = index


class SarifParser(object):
    """
        This class parse Acunetix XML file using helper methods from 'parser_helper.py'.
    """
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
    for item in run['tool']['driver']['rules']:
        rules[item['id']] = item
    return rules

def get_artifacts(run):
    artifacts = {}
    custom_index = 0 # hack because some tool doesn't generate this attribute
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
    cve = None
    cwe = None
    active = True
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
    severity = get_severity(rule['defaultConfiguration'].get('level'))

    if 'shortDescription' in rule:
        title = get_message(rule['shortDescription'])
        description = get_message(rule['shortDescription'])
    else:
        title = finding['message'].get('text', 'No text')
        description = get_message(rule['fullDescription'])


    finding = Finding(title=finding['ruleId'],
                      test=test,
                      severity=severity,
                      numerical_severity=Finding.get_numerical_severity(severity),
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
                      impact="No impact provided",
                      static_finding=True, # by definition
                      dynamic_finding=False, # by definition
                      file_path=file_path,
                      line=line)

    return finding
