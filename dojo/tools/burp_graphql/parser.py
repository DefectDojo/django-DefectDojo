import logging
import json
import re


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
            find = Finding(title=issue.get('issue_type').get('name'),
                           description=issue.get('description_html'),
                           test=test,
                           severity=issue.get('severity').capitalize(),
                           mitigation=issue.get('remediation_html'),
                           references=issue.get('issue_type').get('references_html'),
                           impact=issue.get('issue_type').get('description_html'),
                           cwe=self.get_cwe(issue.get('issue_type').get('vulnerability_classifications_html')),
                           false_p=False,
                           duplicate=False,
                           out_of_scope=False,
                           mitigated=None,
                           static_finding=False,
                           dynamic_finding=True,
                           nb_occurences=1)


            if issue.get('evidence'):

                unsaved_req_resp = list()

                for evidence in issue.get('evidence'):

                    evidence_len = len(evidence)

                    i = 0
                    while i < evidence_len:

                        request = ""
                        request_dict = evidence[i]


                        for data in request_dict.get('request_segments'):

                            if data.get('data_html'):
                                request += data.get('data_html')
                            elif data.get('highlight_html'):
                                request += data.get('highlight_html')

                        if (i + 1) < evidence_len and evidence[i + 1].get('response_segments') and \
                                evidence[i + 1].get('response_index') == request_dict.get('request_index'):

                            response = ""
                            response_dict = evidence[i + 1]

                            for data in response_dict.get('response_segments'):
                                if data.get('data_html'):
                                    response += data.get('data_html')
                                elif data.get('highlight_html'):
                                    response += data.get('highlight_html')
                                    
                            i += 2
                            unsaved_req_resp.append({"req": request, "resp": response})
                            
                        else:
                            unsaved_req_resp.append({"req": request, "resp": ""})
                            i += 1
                    
                find.unsaved_req_resp = unsaved_req_resp

            find.unsaved_endpoints = issue.get('endpoints')
            items.append(find)

        return items

    def get_cwe(self, cwe_html):
        # Match only the first CWE!
        cweSearch = re.search("CWE-([0-9]*)", cwe_html, re.IGNORECASE)
        if cweSearch:
            return cweSearch.group(1)
        else:
            return 0

