__author__ = 'aaronweaver'

import re
from defusedxml import ElementTree as ET
import hashlib
from urlparse import urlparse

from dojo.models import Finding, Endpoint


class NiktoXMLParser(object):

    def __init__(self, filename, test):
        dupes = dict()
        self.items = ()

        if filename is None:
            self.items = ()
            return

        tree = ET.parse(filename)
        root = tree.getroot()
        scan = root.find('scandetails')

        for item in scan.findall('item'):
            # Title
            titleText = None
            description = item.find("description").text
            # Cut the title down to the first sentence
            sentences = re.split(
                r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?)\s', description)
            if len(sentences) > 0:
                titleText = sentences[0][:900]
            else:
                titleText = description[:900]

            # Url
            ip = item.find("iplink").text
            # Remove the port numbers for 80/443
            ip = ip.replace(":80", "")
            ip = ip.replace(":443", "")

            # Severity
            severity = "Info"  # Nikto doesn't assign severity, default to Info

            # Description
            description = "\nHost: " + ip + "\n" + \
                item.find("description").text
            mitigation = "N/A"
            impact = "N/A"
            references = "N/A"

            dupe_key = hashlib.md5(description).hexdigest()

            if dupe_key in dupes:
                finding = dupes[dupe_key]
                if finding.description:
                    finding.description = finding.description + "\nHost:" + ip + "\n" + description
                self.process_endpoints(finding, ip)
                dupes[dupe_key] = finding
            else:
                dupes[dupe_key] = True

                finding = Finding(title=titleText,
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
                self.process_endpoints(finding, ip)

        self.items = dupes.values()

    def process_endpoints(self, finding, host):
        protocol = "http"
        query = ""
        fragment = ""
        path = ""
        url = urlparse(host)

        if url:
            path = url.path

        rhost = re.search(
            "(http|https|ftp)\://([a-zA-Z0-9\.\-]+(\:[a-zA-Z0-9\.&amp;%\$\-]+)*@)*((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|localhost|([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.(com|edu|gov|int|mil|net|org|biz|arpa|info|name|pro|aero|coop|museum|[a-zA-Z]{2}))[\:]*([0-9]+)*([/]*($|[a-zA-Z0-9\.\,\?\'\\\+&amp;%\$#\=~_\-]+)).*?$",
            host)
        protocol = rhost.group(1)
        host = rhost.group(4)

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
