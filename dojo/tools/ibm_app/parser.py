import hashlib
import logging

from defusedxml import ElementTree

from dojo.models import Endpoint, Finding

LOGGER = logging.getLogger(__name__)


class IbmAppParser(object):

    def get_scan_types(self):
        return ["IBM AppScan DAST"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "XML file from IBM App Scanner."

    def get_findings(self, file, test):

        ibm_scan_tree = ElementTree.parse(file)
        root = ibm_scan_tree.getroot()

        # validate XML file
        if 'xml-report' not in root.tag:
            raise ValueError("This does not look like a valid expected Ibm AppScan DAST XML file.")

        issue_list = []
        # self.hosts = self.fetch_host_details()
        issue_types = self.fetch_issue_types(root)
        dupes = dict()
        # Now time to loop through individual issues and perform necessary actions
        for issue in root.iter("issue-group"):
            for item in issue.iter("item"):
                ref_link = ""
                if item.find("issue-type/ref") is not None:
                    recommendation_data = ""
                    issue_data = issue_types[item.find("issue-type/ref").text]

                    name = issue_data['name']
                    # advisory = issue_data['advisory']
                    vulnerability_id = issue_data.get('cve')

                    cwe = issue_data.get('cwe')
                    if cwe:
                        cwe = int(cwe)

                    url = self.get_url(root, item.find('url/ref').text)

                    severity = item.find('severity').text.capitalize()
                    if severity == 'Informational':
                        severity = 'Info'
                    issue_description = self.fetch_advisory_group(root, issue_data['advisory'])

                    for fix_recommendation_group in root.iter("fix-recommendation-group"):
                        for recommendation in fix_recommendation_group.iter("item"):
                            if recommendation.attrib['id'] == issue_data["fix-recommendation"]:
                                data = recommendation.find("general/fixRecommendation")
                                for data_text in data.iter("text"):
                                    recommendation_data += data_text.text + "\n"  # some texts are being repeated

                                for link in data.iter('link'):
                                    if link is not None:
                                        ref_link += link.text + "\n"

                    # Now time to start assigning issues to findings and endpoints
                    dupe_key = hashlib.md5(str(issue_description + name + severity).encode('utf-8')).hexdigest()
                    # check if finding is a duplicate
                    if dupe_key in dupes:
                        finding = dupes[dupe_key]  # fetch finding
                        if issue_description is not None:
                            finding.description += issue_description
                    else:  # finding is not a duplicate
                        # create finding
                        finding = Finding(title=name,
                                          test=test,
                                          cwe=cwe,
                                          description=issue_description,
                                          severity=severity,
                                          mitigation=recommendation_data,
                                          references=ref_link,
                                          dynamic_finding=True)
                        if vulnerability_id:
                            finding.unsaved_vulnerability_ids = [vulnerability_id]
                        finding.unsaved_endpoints = list()
                        dupes[dupe_key] = finding

                        # in case empty string is returned as url
                        # this condition is very rare to occur
                        # As most of the actions of any vuln scanner depends on urls
                        if url:
                            finding.unsaved_endpoints.append(Endpoint.from_uri(url))

        return list(dupes.values())

    # Loop through file and fetch all issue-types found
    def fetch_issue_types(self, root):
        issues = {}
        for issue_type in root.iter("issue-type-group"):
            for item in issue_type.iter("item"):
                issues[item.attrib['id']] = {
                    'name': item.find("name").text,
                    'advisory': item.find("advisory/ref").text,
                    'fix-recommendation': item.find("fix-recommendation/ref").text
                }

                cve = item.find("cve").text
                if cve is not None:
                    issues[item.attrib['id']]['cve'] = cve

                # cwe can be a link
                cwe = item.find("cwe/link")
                if cwe is None:
                    cwe = item.find("cwe")
                if cwe.text is not None:
                    issues[item.attrib['id']]['cwe'] = int(cwe.text)

        return issues

    # this fetches Issue description
    def fetch_advisory_group(self, root, advisory):
        """
        Function that parse advisory-group in order to get the item's description
        """
        for advisory_group in root.iter("advisory-group"):
            for item in advisory_group.iter("item"):
                if item.attrib['id'] == advisory:
                    return item.find('advisory/testTechnicalDescription/text').text
        return "N/A"

    def get_url(self, root, ref):
        for url_group in root.iter('url-group'):
            for item in url_group.iter('item'):
                if item.attrib['id'] == ref:
                    return item.find('name').text

        return None  # This case is very rare to occur
