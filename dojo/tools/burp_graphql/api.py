import requests
import logging
import re

from dojo.models import Endpoint

logger = logging.getLogger(__name__)


class BurpGraphQLAPI:
    def __init__(self, api_key, endpoint, site_id):
        self.key = api_key
        self.url = endpoint
        self.id = site_id
        self.findings = []
        self.headers = {
            'Authorization': api_key,
            'Content-Type': 'application/json'
        }

        if not self.key:
            raise Exception(
                'Please supply a BurpSuite API key. \n'
                'See TODO ADD URL \n'
            )
        if not self.url:
            raise Exception(
                'Please supply a BurpSuite GraphQL API url. \n'
                'See TODO ADD URL \n'
            )

        if not self.id:
            raise Exception(
                'Please supply the id of a site in BurpSuite Enterprise. \n'
                'See TODO ADD URL \n'
            )
        if self.url.endswith('/'):
            self.url = endpoint[:-1]

        self.session = requests.Session()

        self.get_findings()



    def get_findings(self):
        query = """
        query GetScans ($id: ID!) {
            scans(
                offset: 0,
                limit: 1,
                scan_status: succeeded,
                site_id: $id,
                sort_order: desc) {
                    id
                    issue_counts {
                        total
                    }
                }
        }
        """

        # Find the total number of issues associated with the scan
        variables = {'id': self.id}

        response = requests.post(self.url, json = {'query': query, 'variables': variables}, headers = self.headers)

        scan_data = response.json()

        issue_count = scan_data['data']['scans'][0]['issue_counts']['total']
        scan_id = scan_data['data']['scans'][0]['id']


        # Get all the issues from the scan

        query = """
        query GetScan ($id: ID!, $count: Int!) {
            scan(id: $id) {
                issues(start: 0, count: $count) {
                    serial_number
                }
            }
        }
        """

        variables = {'id': scan_id, 'count': issue_count}

        response = requests.post(self.url, json = {'query': query, 'variables': variables}, headers = self.headers)
        self.findings = self.get_finding_details(response.json()['data']['scan']['issues'], scan_id)
        

    def get_finding_details(self, findings_json, scan_id):

        query = """query Issue ($id: ID!, $snum: ID!){
                issue(scan_id: $id, serial_number: $snum) {
                    issue_type {
                        name
                        description_html
                        remediation_html
                        vulnerability_classifications_html
                        references_html
                    }
                    description_html
                    remediation_html
                    severity
                    path
                    origin
                    evidence {
                    ... on Request {
                        request_index
                        request_segments {
                            ... on DataSegment {
                                data_html
                            }
                            ... on HighlightSegment {
                                highlight_html
                            }
                        }
                    }
                    ... on Response {
                        response_index
                        response_segments {
                            ... on DataSegment {
                                data_html
                            }
                            ... on HighlightSegment {
                                highlight_html
                            }
                        }
                    }
                }
            }
        }"""
        
        issue_dict = dict()

        for issue in findings_json:
            variables = {'id': scan_id, 'snum': issue['serial_number']}

            response = requests.post(self.url, json = {'query': query, 'variables': variables}, headers = self.headers)

            issue_json = response.json()['data']['issue']
            
            issue_name = issue_json['issue_type']['name']

            if issue_dict.get(issue_name):
                self.combine_findings(issue_dict.get(issue_name), issue_json)
            else:
                finding = self.create_finding(issue_json)
                if finding:
                    issue_dict[issue_name] = finding

        
        return list(issue_dict.values())

    def combine_findings(self, finding, issue):

        description = issue.get('description_html')

        if description:
            if not finding['Description'].count(description) > 0:
                finding['Description'] += description + "\n\n"

        if issue.get('evidence'):
            finding['Evidence'] = finding['Evidence'] + self.parse_evidence(issue.get('evidence'))
            
        finding['Endpoints'].append(Endpoint.from_uri(issue['origin'] + issue['path']))

    def create_finding(self, issue):
        finding = dict()
        finding['Impact'] = ''
        finding['Description'] = ''
        finding['Mitigation'] = ''
        
        if issue['issue_type'] and issue['issue_type'].get('name'):
            finding['Title'] = issue['issue_type']['name']
        else:
            return None

        if issue.get('description_html'):
            finding['Description'] += "**Issue Detail**\n"
            finding['Description'] += issue.get('description_html') + "\n\n"
            
            if issue['issue_type'].get('description_html'):
                finding['Impact'] += "**Issue Background**\n"
                finding['Impact'] += issue['issue_type'].get('description_html') + "\n\n"
        elif issue['issue_type'].get('description_html'):
            finding['Description'] += "**Issue Background**\n"
            finding['Description'] += issue['issue_type'].get('description_html') + "\n\n"

        if issue.get('remediation_html'):
            finding['Mitigation'] += "**Remediation Detail**\n"
            finding['Mitigation'] += issue.get('remediation_html') + "\n\n"

            if issue['issue_type'].get('remediation_html'):
                finding['Mitigation'] += "**Remediation Background**\n"
                finding['Mitigation'] += issue['issue_type'].get('remediation_html') + "\n\n"
        elif issue['issue_type'].get('remediation_html'):
            finding['Impact'] += "**Remediation Background**\n"
            finding['Impact'] += issue['issue_type'].get('remediation_html') + "\n\n"

        finding['Severity'] = issue['severity'].capitalize()
        finding['Endpoints'] = [Endpoint.from_uri(issue['origin'] + issue['path'])]

        if issue.get('evidence'):
            finding['Evidence'] = self.parse_evidence(issue.get('evidence'))
        else:
            finding['Evidence'] = []

        finding['References'] = issue.get('references_html')

        finding['CWE'] = self.get_cwe(issue['issue_type'].get('vulnerability_classifications_html'))

        return finding

    def parse_evidence(self, evidence):

        evidence_len = len(evidence)
        req_resp_list = list()

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
                req_resp_list.append({"req": request, "resp": response})
                            
            else:
                req_resp_list.append({"req": request, "resp": ""})
                i += 1
                    
        return req_resp_list


    def get_cwe(self, cwe_html):
        # Match only the first CWE!

        if not cwe_html:
            return 0

        cweSearch = re.search("CWE-([0-9]*)", cwe_html, re.IGNORECASE)
        if cweSearch:
            return cweSearch.group(1)
        else:
            return 0
