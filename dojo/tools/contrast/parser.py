__author__ = 'aaronweaver'

import pandas as pd
import hashlib
from dojo.models import Finding, Endpoint


class ContrastCSVParser(object):

    def __init__(self, filename, test):
        dupes = dict()
        self.items = ()

        if filename is None:
            self.items = ()
            return

        df = pd.read_csv(filename, header=0)

        for i, row in df.iterrows():
            # Vulnerability Name,Vulnerability ID,Category,Rule Name,Severity,Status,Number of Events,First Seen,Last Seen,Application Name,Application ID,Application Code,CWE ID,Request Method,Request Port,Request Protocol,Request Version,Request URI,Request Qs,Request Body
            cwe = self.format_cwe(df.ix[i, 'CWE ID'])
            title = df.ix[i, 'Rule Name']
            category = df.ix[i, 'Category']
            description = self.format_description(df, i)
            severity = df.ix[i, 'Severity']
            if severity == "Note":
                severity = "Info"
            mitigation = "N/A"
            impact = "N/A"
            references = "N/A"

            dupe_key = hashlib.md5(category + '|' + str(cwe) + '|' + title + '|').hexdigest()

            if dupe_key in dupes:
                finding = dupes[dupe_key]
                if finding.description:
                    finding.description = finding.description + "\nVulnerability ID: " + \
                        df.ix[i, 'Vulnerability ID'] + "\n" + \
                        df.ix[i, 'Vulnerability Name'] + "\n"
                self.process_endpoints(finding, df, i)
                dupes[dupe_key] = finding
            else:
                dupes[dupe_key] = True

                finding = Finding(title=title,
                                  cwe=int(cwe),
                                  test=test,
                                  active=False,
                                  verified=False,
                                  description=description,
                                  severity=severity,
                                  numerical_severity=Finding.get_numerical_severity(
                                      severity),
                                  mitigation=mitigation,
                                  impact=impact,
                                  references=references,
                                  url='N/A',
                                  dynamic_finding=True)

                dupes[dupe_key] = finding
                self.process_endpoints(finding, df, i)

        self.items = dupes.values()

    def format_description(self, df, i):
        description = "Request URI: " + str(df.ix[i, 'Request URI']) + "\n"
        description = "Rule Name: " + df.ix[i, 'Rule Name'] + "\n"
        description = "Vulnerability ID: " + \
            df.ix[i, 'Vulnerability ID'] + "\n"
        description = description + df.ix[i, 'Vulnerability Name'] + "\n\n"
        if pd.isnull(df.ix[i, 'Request Qs']) is False:
            description = description + "Request QueryString: " + \
                str(df.ix[i, 'Request Qs']) + "\n"
        if pd.isnull(df.ix[i, 'Request Body']):
            description = description + "Request Body: " + \
                str(df.ix[i, 'Request Body']) + "\n"
        return description

    def format_cwe(self, url):
        # Get the last path
        filename = url.rsplit('/', 1)[1]

        # Split out the . to get the CWE id
        filename = filename.split('.')[0]

        return filename

    def process_endpoints(self, finding, df, i):
        protocol = "http"
        host = "0.0.0.0"
        query = ""
        fragment = ""
        path = df.ix[i, 'Request URI']

        if pd.isnull(path) is False:
            try:
                dupe_endpoint = Endpoint.objects.get(protocol="protocol",
                                                     host=host,
                                                     query=query,
                                                     fragment=fragment,
                                                     path=path,
                                                     product=finding.test.engagement.product)
            except Endpoint.DoesNotExist:
                dupe_endpoint = None

            if not dupe_endpoint:
                endpoint = Endpoint(protocol=protocol,
                                    host=host,
                                    query=query,
                                    fragment=fragment,
                                    path=path,
                                    product=finding.test.engagement.product)
            else:
                endpoint = dupe_endpoint

            if not dupe_endpoint:
                endpoints = [endpoint]
            else:
                endpoints = [endpoint, dupe_endpoint]

            finding.unsaved_endpoints = finding.unsaved_endpoints + endpoints
