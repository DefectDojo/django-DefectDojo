from xml.dom import NamespaceErr
import hashlib
from urllib.parse import urlparse
from dojo.models import Endpoint, Finding
from defusedxml import ElementTree

__author__ = 'propersam'


class IbmAppScanDASTXMLParser(object):
    def __init__(self, file, test):
        self.items = ()

        if file is None:
            return

        ibm_scan_tree = ElementTree.parse(file)
        self.root = ibm_scan_tree.getroot()

        # validate XML file
        if 'xml-report' not in self.root.tag:
            raise NamespaceErr("This does not look like a valid expected Ibm AppScan DAST XML file.")

        self.issue_list = []
        # self.hosts = self.fetch_host_details()
        self.issue_types = self.fetch_issue_types()
        self.dupes = dict()
        # Now time to loop through individual issues and perform necessary actions
        for issue in self.root.iter("issue-group"):
            for item in issue.iter("item"):
                impact = "N/A"

                ref_link = ""
                if item.find("issue-type/ref") is not None:
                    recommendation_data = ""
                    issue_data = self.issue_types[item.find("issue-type/ref").text]

                    name = issue_data['name']
                    # advisory = issue_data['advisory']

                    cve = None
                    if "cve" in issue_data:
                        cve = issue_data['cve']

                    url = self.get_url(item.find('url/ref').text)
                    # in case empty string is returned as url
                    # this condition is very rare to occur
                    # As most of the actions of any vuln scanner depends on urls
                    if url == "N/A":
                        host = "N/A"
                        path = ""
                        scheme = "N/A"
                        port = ""
                        query = ""
                    else:
                        host = urlparse(url).netloc
                        path = urlparse(url).path
                        scheme = urlparse(url).scheme
                        if scheme == "https":
                            port = '443'
                        else:
                            port = '80'
                        query = urlparse(url).query

                    severity = item.find('severity').text.capitalize()
                    issue_description = self.fetch_advisory_group(issue_data['advisory'])

                    for fix_recommendation_group in self.root.iter("fix-recommendation-group"):
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
                    if dupe_key in self.dupes:
                        finding = self.dupes[dupe_key]  # fetch finding
                        if issue_description is not None:
                            finding.description += issue_description
                    else:  # finding is not a duplicate
                        # create finding
                        finding = Finding(title=name,
                                          test=test, active=False,
                                          verified=False, cve=cve,
                                          description=issue_description,
                                          severity=severity,
                                          numerical_severity=Finding.get_numerical_severity(
                                              severity
                                          ),
                                          mitigation=recommendation_data,
                                          impact=impact,
                                          references=ref_link,
                                          dynamic_finding=True)

                        finding.unsaved_endpoints = list()
                        self.dupes[dupe_key] = finding

                        finding.unsaved_endpoints.append(Endpoint(
                            host=host, port=port,
                            path=path,
                            protocol=scheme,
                            query=query
                        ))

            self.items = self.dupes.values()

    # Loop through file and fetch all issue-types found
    def fetch_issue_types(self):
        issues = {}
        for issue_type in self.root.iter("issue-type-group"):
            for item in issue_type.iter("item"):
                issues[item.attrib['id']] = {
                    'name': item.find("name").text,
                    'advisory': item.find("advisory/ref").text,
                    'fix-recommendation': item.find("fix-recommendation/ref").text
                }

                if "cve" in issue_type:
                    issues[issue_type.attrib['id']] = {'cve': issue_type.find("cve").text}

        return issues

    # this fetches Issue description
    def fetch_advisory_group(self, advisory):
        """
        Function that parse advisory-group in order to get the item's description
        """
        for advisory_group in self.root.iter("advisory-group"):
            for item in advisory_group.iter("item"):
                if item.attrib['id'] == advisory:
                    return item.find('advisory/testTechnicalDescription/text').text
        return "N/A"

    def get_url(self, ref):
        for url_group in self.root.iter('url-group'):
            for item in url_group.iter('item'):
                if item.attrib['id'] == ref:
                    return item.find('name').text

        return "N/A"  # This case is very rare to occur
