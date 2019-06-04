from xml.dom import NamespaceErr
import hashlib
from urlparse import urlparse
from dojo.models import Endpoint, Finding
from defusedxml import ElementTree

__author__ = 'properam'


class ImmuniwebXMLParser(object):
    def __init__(self, file, test):
        self.items = ()
        if file is None:
            return

        ImmuniScanTree = ElementTree.parse(file)
        root = ImmuniScanTree.getroot()
        # validate XML file
        if 'Vulnerabilities' not in root.tag:
            raise NamespaceErr("This does not look like a valid expected Immuniweb XML file.")

        self.dupes = dict()

        for vulnerability in root.iter("Vulnerability"):
            """
                The Tags available in XML File are:
                ID, Name, Date, Status,
                Type, CWE_ID, CVE_ID, CVSSv3,
                Risk, URL, Description, PoC
            """
            mitigation = "N/A"
            impact = "N/A"
            title = vulnerability.find('Name').text
            reference = vulnerability.find('ID').text
            cwe = vulnerability.find('CWE-ID').text
            cve = vulnerability.find('CVE-ID').text
            steps_to_reproduce = vulnerability.find('PoC').text
            # just to make sure severity is in the recognised sentence casing form
            severity = vulnerability.find('Risk').text.capitalize()
            # Set 'Warning' severity === 'Informational'
            if severity == 'Warning':
                severity = "Informational"

            description = (vulnerability.find('Description').text).encode('utf-8')
            url = vulnerability.find("URL").text
            parsedUrl = urlparse(url)
            protocol = parsedUrl.scheme
            query = parsedUrl.query
            fragment = parsedUrl.fragment
            path = parsedUrl.path
            port = ""  # Set port to empty string by default
            # Split the returned network address into host and
            try:  # If there is port number attached to host address
                host, port = parsedUrl.netloc.split(':')
            except:  # there's no port attached to address
                host = parsedUrl.netloc

            dupe_key = hashlib.md5(description + title + severity).hexdigest()

            # check if finding is a duplicate
            if dupe_key in self.dupes:
                finding = self.dupes[dupe_key]  # fetch finding
                if description is not None:
                    finding.description += description
            else:  # finding is not a duplicate
                # create finding
                finding = Finding(title=title,
                    test=test, active=False,
                    verified=False, cve=cve,
                    description=description,
                    severity=severity,
                    steps_to_reproduce=steps_to_reproduce,
                    numerical_severity=Finding.get_numerical_severity(
                        severity
                    ),
                    mitigation=mitigation,
                    impact=impact,
                    references=reference,
                    dynamic_finding=True)

                finding.unsaved_endpoints = list()
                self.dupes[dupe_key] = finding

                finding.unsaved_endpoints.append(Endpoint(
                        host=host, port=port,
                        path=path,
                        protocol=protocol,
                        query=query, fragment=fragment))

        self.items = self.dupes.values()
