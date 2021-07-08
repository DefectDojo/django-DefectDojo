import requests
import logging

from dojo.models import Endpoint

logger = logging.getLogger(__name__)


class BurpGraphQLAPI:
    def __init__(self, api_key, endpoint, site_id):
        self.key = api_key
        self.url = endpoint
        self.id = site_id
        self.findings = []

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
        headers = {
            'Authorization': self.key,
            'Content-Type': 'application/json'
        }

        response = requests.post(self.url, json = {'query': query, 'variables': variables}, headers = headers)

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

        query2 = """query Issue ($id: ID!, $snum: ID!){
                issue(scan_id: $id, serial_number: $snum) {
                    issue_type {
                        type_index
                        name
                        description_html
                        remediation_html
                        vulnerability_classifications_html
                        references_html
                    }
                    confidence
                    display_confidence 
                    serial_number
                    description_html
                    remediation_html
                    severity
                    path
                    origin
                    novelty
                    evidence {
                    ... on Request {
                        request_index
                        request_count
                        request_segments {
                            ... on DataSegment {
                                data_html
                            }
                            ... on HighlightSegment {
                                highlight_html
                            }
                            ... on SnipSegment {
                                snip_length
                            }
                        }
                    }
                    ... on Response {
                        response_index
                        response_count
                        response_segments {
                            ... on DataSegment {
                                data_html
                            }
                            ... on HighlightSegment {
                                highlight_html
                            }
                            ... on SnipSegment {
                                snip_length
                            }
                        }
                    }
                    ... on HttpInteraction {
                        title
                        description_html
                        request {
                            ... on DataSegment {
                                data_html
                            }
                            ... on HighlightSegment {
                                highlight_html
                            }
                            ... on SnipSegment {
                                snip_length
                            }
                        }
                        response {
                            ... on DataSegment {
                                data_html
                            }
                            ... on HighlightSegment {
                                highlight_html
                            }
                            ... on SnipSegment {
                                snip_length
                            }
                        }
                    }
                    ... on DescriptiveEvidence {
                        title
                        description_html
                    }
                }
            }
        }"""

        variables = {'id': scan_id, 'count': issue_count}

        response = requests.post(self.url, json = {'query': query, 'variables': variables}, headers = headers)
        response_json = response.json()
        issue_dict = dict()

        for issue in response_json['data']['scan']['issues']:
            variables = {'id': scan_id, 'snum': issue['serial_number']}

            response = requests.post(self.url, json = {'query': query2, 'variables': variables}, headers = headers)

            issue_json = response.json()['data']['issue']
            
            issue_name = issue_json['issue_type']['name']

            if issue_dict.get(issue_name):

                if issue_dict[issue_name]['description_html'] and issue_json['description_html']:
                    issue_dict[issue_name]['description_html'] += '\n\n' + issue_json['description_html']
                elif issue_json['description_html']:
                    issue_dict[issue_name]['description_html'] = issue_json['description_html']

                if issue_dict[issue_name]['remediation_html'] and issue_json['remediation_html']:
                    issue_dict[issue_name]['remediation_html'] += '\n\n' + issue_json['remediation_html']
                elif issue_json['remediation_html']:
                    issue_dict[issue_name]['remediation_html'] = issue_json['remediation_html']

                issue_dict[issue_name]['evidence'].append(issue_json['evidence'])
                issue_dict[issue_name]['endpoints'].append(Endpoint.from_uri(issue_json['origin'] + issue_json['path']))
            else:
                issue_dict[issue_name] = issue_json
                issue_dict[issue_name]['evidence'] = [issue_json['evidence']]
                issue_dict[issue_name]['endpoints'] = [Endpoint.from_uri(issue_json['origin'] + issue_json['path'])]

            if not issue_dict[issue_name].get('description_html'):
                issue_dict[issue_name]['description_html'] = ''

        
        self.findings = list(issue_dict.values())
