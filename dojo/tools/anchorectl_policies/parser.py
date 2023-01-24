import json
import logging
import re
from datetime import datetime
from json.decoder import JSONDecodeError

from dojo.models import Finding

logger = logging.getLogger(__name__)


class AnchoreCTLPoliciesParser:

    def get_scan_types(self):
        return ["AnchoreCTL Policies Report"]

    def get_label_for_scan_types(self, scan_type):
        return "AnchoreCTL Policies Report"

    def get_description_for_scan_types(self, scan_type):
        return "AnchoreCTLs JSON policies report format."

    def get_findings(self, filename, test):
        content = filename.read()
        try:
            data = json.loads(str(content, 'utf-8'))
        except (JSONDecodeError, TypeError):
            data = json.loads(content)

        find_date = datetime.now()
        items = list()
        try:
            for image in data:
                for result in image['detail']:
                    try:
                        gate = result['gate']
                        description = result['description']
                        policy_id = result['policyId']
                        status = result['status']
                        image_name = result['tag']
                        trigger_id = result['triggerId']
                        repo, tag = image_name.split(':', 2)
                        severity = map_gate_action_to_severity(status)
                        vulnerability_id = extract_vulnerability_id(trigger_id)
                        title = policy_id + ' - gate|' + gate + ' - trigger|' + trigger_id
                        find = Finding(
                            title=title,
                            test=test,
                            description=description,
                            severity=severity,
                            references="Policy ID: {}\nTrigger ID: {}".format(policy_id, trigger_id),
                            file_path=search_filepath(description),
                            component_name=repo,
                            component_version=tag,
                            date=find_date,
                            static_finding=True,
                            dynamic_finding=False)
                        if vulnerability_id:
                            find.unsaved_vulnerability_ids = [vulnerability_id]
                        items.append(find)
                    except (KeyError, IndexError) as err:
                        raise Exception("Invalid format: {} key not found".format(err))
        except AttributeError as err:
            # import empty policies without error (e.g. policies or images objects are not a dictionary)
            logger.warning('Exception at %s', 'parsing anchore policy', exc_info=err)
        return items


def map_gate_action_to_severity(gate):
    gate_action_to_severity = {
        'stop': 'Critical',
        'warn': 'Medium',
    }
    if gate in gate_action_to_severity:
        return gate_action_to_severity[gate]
    return 'Low'


def policy_name(policies, policy_id):
    for policy in policies:
        if policy_id == policy['id']:
            return policy['name']
    return "unknown"


def extract_vulnerability_id(trigger_id):
    try:
        vulnerability_id, _ = trigger_id.split('+', 2)
        if vulnerability_id.startswith('CVE'):
            return vulnerability_id
        return None
    except ValueError:
        return None


def search_filepath(text):
    match = re.search(r' (/[^/ ]*)+/?', text)
    path = ""
    if match:
        try:
            path = match.group(0)
        except IndexError:
            path = ""
    return path.strip()
