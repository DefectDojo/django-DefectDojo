import json
import logging
import re
import textwrap
import dateutil.parser
from dojo.tools.parser_test import ParserTest
from dojo.models import Finding

logger = logging.getLogger(__name__)

CWE_REGEX = r'cwe-\d+'


class SarifParser(object):
    """OASIS Static Analysis Results Interchange Format (SARIF) for version 2.1.0 only.

    https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=sarif
    """

    def get_scan_types(self):
        return ["SARIF"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "SARIF report file can be imported in SARIF format."

    def get_findings(self, filehandle, test):
        """For simple interface of parser contract we just aggregate everything"""
        tree = json.load(filehandle)
        items = list()
        # for each runs we just aggregate everything
        for run in tree.get('runs', list()):
            items.extend(self.__get_items_from_run(run))
        return items

    def get_tests(self, scan_type, handle):
        tree = json.load(handle)
        tests = list()
        for run in tree.get('runs', list()):
            test = ParserTest(
                name=run['tool']['driver']['name'],
                type=run['tool']['driver']['name'],
                version=run['tool']['driver'].get('version'),
            )
            test.findings = self.__get_items_from_run(run)
            tests.append(test)
        return tests

    def __get_items_from_run(self, run):
        items = list()
        # load rules
        rules = get_rules(run)
        artifacts = get_artifacts(run)
        # get the timestamp of the run if possible
        run_date = self.__get_last_invocation_date(run)
        for result in run.get('results', list()):
            item = get_item(result, rules, artifacts, run_date)
            if item is not None:
                items.append(item)
        return items

    def __get_last_invocation_date(self, data):
        invocations = data.get('invocations', [])
        if len(invocations) == 0:
            return None
        # try to get the last 'endTimeUtc'
        raw_date = invocations[-1].get('endTimeUtc')
        if raw_date is None:
            return None
        # if the data is here we try to convert it to datetime
        return dateutil.parser.isoparse(raw_date)


def get_rules(run):
    rules = {}
    for item in run['tool']['driver'].get('rules', []):
        rules[item['id']] = item
    return rules


def get_rule_tags(rule):
    if 'properties' not in rule:
        return []
    if 'tags' not in rule['properties']:
        return []
    else:
        return rule['properties']['tags']


def search_cwe(value, cwes):
    matches = re.search(CWE_REGEX, value, re.IGNORECASE)
    if matches:
        cwes.append(int(matches[0].split("-")[1]))


def get_rule_cwes(rule):
    cwes = []
    # data of the specification
    if 'relationships' in rule and type(rule['relationships']) == list:
        for relationship in rule['relationships']:
            value = relationship['target']['id']
            search_cwe(value, cwes)
        return cwes

    for tag in get_rule_tags(rule):
        search_cwe(tag, cwes)
    return cwes


def get_result_cwes_properties(result):
    """Some tools like njsscan store the CWE in the properties of the result"""
    cwes = []
    if 'properties' in result and 'cwe' in result['properties']:
        value = result['properties']['cwe']
        search_cwe(value, cwes)
    return cwes


def get_artifacts(run):
    artifacts = {}
    custom_index = 0  # hack because some tool doesn't generate this attribute
    for tree_artifact in run.get('artifacts', []):
        artifacts[tree_artifact.get('index', custom_index)] = tree_artifact
        custom_index += 1
    return artifacts


def get_message_from_multiformatMessageString(data, rule):
    """Get a message from multimessage struct

    See here for the specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317468
    """
    if rule is not None and 'id' in data:
        text = rule['messageStrings'][data['id']].get('text')
        arguments = data.get('arguments', [])
        # argument substitution
        for i in range(6):  # the specification limit to 6
            substitution_str = "{" + str(i) + "}"
            if substitution_str in text:
                text = text.replace(substitution_str, arguments[i])
            else:
                return text
    else:
        # TODO manage markdown
        return data.get('text')


def cve_try(val):
    # Match only the first CVE!
    cveSearch = re.search("(CVE-[0-9]+-[0-9]+)", val, re.IGNORECASE)
    if cveSearch:
        return cveSearch.group(1).upper()
    else:
        return None


def get_title(result, rule):
    title = None
    if 'message' in result:
        title = get_message_from_multiformatMessageString(result['message'], rule)
    if title is None and rule is not None:
        if 'shortDescription' in rule:
            title = get_message_from_multiformatMessageString(rule['shortDescription'], rule)
        elif 'fullDescription' in rule:
            title = get_message_from_multiformatMessageString(rule['fullDescription'], rule)
        elif 'name' in rule:
            title = rule['name']
        elif 'id' in rule:
            title = rule['id']

    if title is None:
        raise ValueError('No information found to create a title')

    return textwrap.shorten(title, 150)


def get_snippet(result):
    snippet = None
    if 'locations' in result:
        location = result['locations'][0]
        if 'physicalLocation' in location:
            if 'region' in location['physicalLocation']:
                if 'snippet' in location['physicalLocation']['region']:
                    if 'text' in location['physicalLocation']['region']['snippet']:
                        snippet = location['physicalLocation']['region']['snippet']['text']
            if snippet is None and 'contextRegion' in location['physicalLocation']:
                if 'snippet' in location['physicalLocation']['contextRegion']:
                    if 'text' in location['physicalLocation']['contextRegion']['snippet']:
                        snippet = location['physicalLocation']['contextRegion']['snippet']['text']
    return snippet


def get_description(result, rule):
    description = ''
    message = ''
    if 'message' in result:
        message = get_message_from_multiformatMessageString(result['message'], rule)
        description += '**Result message:** {}\n'.format(message)
    if get_snippet(result) is not None:
        description += '**Snippet:**\n```{}```\n'.format(get_snippet(result))
    if rule is not None:
        if 'name' in rule:
            description += '**Rule name:** {}\n'.format(rule.get('name'))
        shortDescription = ''
        if 'shortDescription' in rule:
            shortDescription = get_message_from_multiformatMessageString(rule['shortDescription'], rule)
            if shortDescription != message:
                description += '**Rule short description:** {}\n'.format(shortDescription)
        if 'fullDescription' in rule:
            fullDescription = get_message_from_multiformatMessageString(rule['fullDescription'], rule)
            if fullDescription != message and fullDescription != shortDescription:
                description += '**Rule full description:** {}\n'.format(fullDescription)

    if description.endswith('\n'):
        description = description[:-1]

    return description


def get_references(rule):
    reference = None
    if rule is not None:
        if 'helpUri' in rule:
            reference = rule['helpUri']
        elif 'help' in rule:
            helpText = get_message_from_multiformatMessageString(rule['help'], rule)
            if helpText.startswith('http'):
                reference = helpText

    return reference


def get_severity(result, rule):
    severity = result.get('level')
    if severity is None and rule is not None:
        # get the severity from the rule
        if 'defaultConfiguration' in rule:
            severity = rule['defaultConfiguration'].get('level')

    if 'note' == severity:
        return 'Info'
    elif 'warning' == severity:
        return 'Medium'
    elif 'error' == severity:
        return 'Critical'
    else:
        return 'Medium'


def get_item(result, rules, artifacts, run_date):

    # see https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html / 3.27.9
    kind = result.get('kind', 'fail')
    if kind != 'fail':
        return None

    # if there is a location get it
    file_path = None
    line = None
    if "locations" in result:
        location = result['locations'][0]
        if 'physicalLocation' in location:
            file_path = location['physicalLocation']['artifactLocation']['uri']
            # 'region' attribute is optionnal
            if 'region' in location['physicalLocation']:
                line = location['physicalLocation']['region']['startLine']

    # test rule link
    rule = rules.get(result.get('ruleId'))

    finding = Finding(
        title=get_title(result, rule),
        severity=get_severity(result, rule),
        description=get_description(result, rule),
        static_finding=True,  # by definition
        dynamic_finding=False,  # by definition
        file_path=file_path,
        line=line,
        references=get_references(rule),
    )

    if 'ruleId' in result:
        finding.vuln_id_from_tool = result['ruleId']
        # for now we only support when the id of the rule is a CVE
        finding.cve = cve_try(result['ruleId'])
    # some time the rule id is here but the tool doesn't define it
    if rule is not None:
        cwes_extracted = get_rule_cwes(rule)
        if len(cwes_extracted) > 0:
            finding.cwe = cwes_extracted[-1]

    # manage the case that some tools produce CWE as properties of the result
    cwes_properties_extracted = get_result_cwes_properties(result)
    if len(cwes_properties_extracted) > 0:
        finding.cwe = cwes_properties_extracted[-1]

    # manage fixes provided in the report
    if "fixes" in result:
        finding.mitigation = "\n".join([fix.get('description', {}).get("text") for fix in result["fixes"]])

    if run_date:
        finding.date = run_date

    return finding
