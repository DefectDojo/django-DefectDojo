import logging
import json
import re
import html2text


from dojo.models import Endpoint, Finding

logger = logging.getLogger(__name__)


class BurpGraphQLParser(object):

    def get_scan_types(self):
        return ["Burp GraphQL API"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import Burp Enterprise Edition findings from the GraphQL API"

    def get_findings(self, filename, test):

        data = json.load(filename)

        if "Issues" not in data:
            raise ValueError('No Issues found')

        return self.create_findings(data.get('Issues'), test)

    def create_findings(self, scan_data, test):

        finding_data = self.parse_findings(scan_data)

        items = list()

        for issue in finding_data:
            find = Finding(title=issue.get('Title'),
                           description=issue.get('Description'),
                           test=test,
                           severity=issue.get('Severity'),
                           mitigation=issue.get('Mitigation'),
                           references=issue.get('References'),
                           impact=issue.get('Impact'),
                           cwe=int(issue.get('CWE')),
                           false_p=False,
                           duplicate=False,
                           out_of_scope=False,
                           static_finding=False,
                           dynamic_finding=True,
                           nb_occurences=1)

            find.unsaved_req_resp = issue.get('Evidence')
            find.unsaved_endpoints = issue.get('Endpoints')

            items.append(find)

        return items

    def parse_findings(self, scan_data):

        issue_dict = dict()

        for issue in scan_data:
            if not issue.get('issue_type') or not issue['issue_type'].get('name'):
                raise ValueError('Issue does not have a name')

            issue_name = issue['issue_type']['name']

            if issue_dict.get(issue_name):
                self.combine_findings(issue_dict.get(issue_name), issue)
            else:
                finding = self.create_finding(issue)
                if finding:
                    issue_dict[issue_name] = finding

        return list(issue_dict.values())

    def combine_findings(self, finding, issue):

        if issue.get('description_html'):
            description = html2text.html2text(issue.get('description_html'))

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
        finding['References'] = ''
        finding['Title'] = issue['issue_type']['name']

        if issue.get('description_html'):
            finding['Description'] += "**Issue Detail**\n"
            finding['Description'] += html2text.html2text(issue.get('description_html'))

            if issue['issue_type'].get('description_html'):
                finding['Impact'] += "**Issue Background**\n"
                finding['Impact'] += html2text.html2text(issue['issue_type'].get('description_html'))
        elif issue['issue_type'].get('description_html'):
            finding['Description'] += "**Issue Background**\n"
            finding['Description'] += html2text.html2text(issue['issue_type'].get('description_html'))

        if issue.get('remediation_html'):
            finding['Mitigation'] += "**Remediation Detail**\n"
            finding['Mitigation'] += issue.get('remediation_html')

            if issue['issue_type'].get('remediation_html'):
                finding['Mitigation'] += "**Remediation Background**\n"
                finding['Mitigation'] += html2text.html2text(issue['issue_type'].get('remediation_html'))
        elif issue['issue_type'].get('remediation_html'):
            finding['Impact'] += "**Remediation Background**\n"
            finding['Impact'] += html2text.html2text(issue['issue_type'].get('remediation_html'))

        if issue.get('severity'):
            finding['Severity'] = issue['severity'].capitalize()
        else:
            finding['Severity'] = 'Info'

        finding['Endpoints'] = [Endpoint.from_uri(issue['origin'] + issue['path'])]

        if issue.get('evidence'):
            finding['Evidence'] = self.parse_evidence(issue.get('evidence'))
        else:
            finding['Evidence'] = []

        if issue['issue_type'].get('references_html'):
            finding['References'] += "**References**\n"
            finding['References'] += html2text.html2text(issue['issue_type'].get('references_html'))

        if issue['issue_type'].get('vulnerability_classifications_html'):
            finding['References'] += "**CWE Information**\n"
            finding['References'] += html2text.html2text(issue['issue_type'].get('vulnerability_classifications_html'))
            finding['CWE'] = self.get_cwe(issue['issue_type'].get('vulnerability_classifications_html'))
        else:
            finding['CWE'] = 0

        return finding

    def parse_evidence(self, evidence):

        evidence_len = len(evidence)
        req_resp_list = list()

        i = 0
        while i < evidence_len:

            request = ""
            request_dict = evidence[i]

            if request_dict.get('request_segments'):
                for data in request_dict.get('request_segments'):
                    if data.get('data_html'):
                        request += html2text.html2text(data.get('data_html')).strip()
                    elif data.get('highlight_html'):
                        request += html2text.html2text(data.get('highlight_html')).strip()

            if (i + 1) < evidence_len and evidence[i + 1].get('response_segments') and \
                    evidence[i + 1].get('response_index') == request_dict.get('request_index'):

                response = ""
                response_dict = evidence[i + 1]

                for data in response_dict.get('response_segments'):
                    if data.get('data_html'):
                        response += html2text.html2text(data.get('data_html')).strip()
                    elif data.get('highlight_html'):
                        response += html2text.html2text(data.get('highlight_html')).strip()

                i += 2
                req_resp_list.append({"req": request, "resp": response})

            else:
                req_resp_list.append({"req": request, "resp": ""})
                i += 1

        return req_resp_list

    def get_cwe(self, cwe_html):
        # Match only the first CWE!
        cweSearch = re.search("CWE-([0-9]*)", cwe_html, re.IGNORECASE)
        if cweSearch:
            return cweSearch.group(1)
        else:
            return 0
