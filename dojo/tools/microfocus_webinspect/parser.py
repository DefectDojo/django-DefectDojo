from xml.dom import NamespaceErr
import hashlib
from urllib.parse import urlparse
import re
from defusedxml import ElementTree as ET
from dojo.models import Endpoint, Finding

__author__ = 'dr3dd589'


class Severityfilter:

    def __init__(self):
        self.severity_mapping = {
            '0': 'Info',
            '1': 'Low',
            '2': 'Medium',
            '3': 'High',
                                }
        self.severity = None

    def eval_column(self, column_value):
        if column_value in self.severity_mapping.keys():
            self.severity = self.severity_mapping[column_value]
        else:
            self.severity = 'Info'


class MicrofocusWebinspectXMLParser(object):
    def __init__(self, file, test):
        self.dupes = dict()
        self.items = ()
        if file is None:
            return

        tree = ET.parse(file)
        # get root of tree.
        root = tree.getroot()
        if 'Sessions' not in root.tag:
            raise NamespaceErr("This doesn't seem to be a valid Webinspect xml file.")

        for session in root:
            url = session.find('URL').text
            host = session.find('Host').text
            port = session.find('Port').text
            scheme = session.find('Scheme').text
            issues = session.find('Issues')
            for issue in issues.findall('Issue'):
                title = issue.find('Name').text
                num_severity = issue.find('Severity').text
                severityfilter = Severityfilter()
                severityfilter.eval_column(num_severity)
                severity = severityfilter.severity
                for content in issue.findall('ReportSection'):
                    name = content.find('Name').text
                    if 'Summary' in name:
                        if content.find('SectionText').text:
                            description = content.find('SectionText').text
                        else:
                            description = ""
                    if 'Fix' in name:
                        if content.find('SectionText').text:
                            mitigation = content.find('SectionText').text
                        else:
                            mitigation = ""
                    if 'Reference':
                        if name and content.find('SectionText').text:
                            reference = content.find('SectionText').text
                        else:
                            reference = ""
                Classifications = issue.find('Classifications')
                for content in Classifications.findall('Classification'):

                    if content.text and 'CWE' in content.text:
                        cwe = re.findall(r'\d+', content.attrib['identifier'])[0]
                        description += "\n\n" + content.text + "\n"
                    else:
                        cwe = None
                        description = ""

                # make dupe hash key
                dupe_key = hashlib.md5(str(description + title + severity).encode('utf-8')).hexdigest()
                # check if dupes are present.
                if dupe_key in self.dupes:
                    finding = self.dupes[dupe_key]
                    if finding.description:
                        finding.description = finding.description
                    self.process_endpoints(finding, host)
                    self.dupes[dupe_key] = finding
                else:
                    self.dupes[dupe_key] = True

                    finding = Finding(title=title,
                                    test=test,
                                    active=False,
                                    verified=False,
                                    cwe=cwe,
                                    description=description,
                                    severity=severity,
                                    numerical_severity=Finding.get_numerical_severity(
                                        severity),
                                    mitigation=mitigation,
                                    references=reference,
                                    dynamic_finding=True)

                    self.dupes[dupe_key] = finding
                    self.process_endpoints(finding, host)

            self.items = list(self.dupes.values())

    def process_endpoints(self, finding, host):
        protocol = "http"
        query = ""
        fragment = ""
        path = ""
        url = urlparse(host)

        if url:
            path = url.path
            if path == host:
                path = ""

        rhost = re.search(
            r"(http|https|ftp)\://([a-zA-Z0-9\.\-]+(\:[a-zA-Z0-9\.&amp;%\$\-]+)*@)*((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|localhost|([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.(com|edu|gov|int|mil|net|org|biz|arpa|info|name|pro|aero|coop|museum|[a-zA-Z]{2}))[\:]*([0-9]+)*([/]*($|[a-zA-Z0-9\.\,\?\'\\\+&amp;%\$#\=~_\-]+)).*?$",
            host)
        try:
            protocol = rhost.group(1)
            host = rhost.group(4)
        except:
            pass
        try:
            dupe_endpoint = Endpoint.objects.get(protocol=protocol,
                                                 host=host,
                                                 query=query,
                                                 fragment=fragment,
                                                 path=path
                                                 )
        except Endpoint.DoesNotExist:
            dupe_endpoint = None

        if not dupe_endpoint:
            endpoint = Endpoint(protocol=protocol,
                                host=host,
                                query=query,
                                fragment=fragment,
                                path=path
                                )
        else:
            endpoint = dupe_endpoint

        if not dupe_endpoint:
            endpoints = [endpoint]
        else:
            endpoints = [endpoint, dupe_endpoint]

        finding.unsaved_endpoints = finding.unsaved_endpoints + endpoints
