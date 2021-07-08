import logging
import json


from dojo.models import Endpoint, Finding
from dojo.tools.burp_graphql.api import BurpGraphQLAPI

logger = logging.getLogger(__name__)


class BurpGraphQLParser(object):

    def get_scan_types(self):
        return ["Burp Enterprise Scan GraphQL API"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import Burp Enterprise Edition findings from the GraphQL API"

    def get_findings(self, filename, test):
        if filename:
            tree = filename.read()
            try:
                data = json.loads(str(tree, 'utf-8'))
            except:
                data = json.loads(tree)

            api = BurpGraphQLAPI(
                data.get('api_key', None),
                data.get('url_endpoint', None),
                data.get('site_id', None),
            )
            scan_data = api.findings

            return self._parse_findings(scan_data, test)

    def _parse_findings(self, scan_data, test):
        
        items = list()

        for issue in scan_data:
            find = Finding(title=issue.get('Title'),
                           description=issue.get('Description'),
                           test=test,
                           severity=issue.get('Severity'),
                           mitigation=issue.get('Mitigation'),
                           references=issue.get('References'),
                           impact=issue.get('Impact'),
                           cwe=issue.get('CWE'),
                           false_p=False,
                           duplicate=False,
                           out_of_scope=False,
                           mitigated=None,
                           static_finding=False,
                           dynamic_finding=True,
                           nb_occurences=1)

            find.unsaved_req_resp = issue.get('Evidence')
            find.unsaved_endpoints = issue.get('Endpoints')

            items.append(find)

        return items

    

