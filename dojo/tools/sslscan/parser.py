import hashlib
from xml.dom import NamespaceErr

from defusedxml import ElementTree as ET

from dojo.models import Endpoint, Finding

__author__ = 'dr3dd589'


class SslscanParser(object):

    def get_scan_types(self):
        return ["Sslscan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import XML output of sslscan report."

    def get_findings(self, file, test):
        tree = ET.parse(file)
        # get root of tree.
        root = tree.getroot()
        if 'document' not in root.tag:
            raise NamespaceErr("This doesn't seem to be a valid sslscan xml file.")
        dupes = dict()
        for ssltest in root:
            for target in ssltest:
                title = ""
                severity = ""
                description = ""
                severity = "Info"
                host = ssltest.attrib['host']
                port = int(ssltest.attrib['port'])
                if target.tag == "heartbleed" and target.attrib['vulnerable'] == '1':
                    title = "heartbleed" + " | " + target.attrib['sslversion']
                    description = "**heartbleed** :" + "\n\n" + \
                                "**sslversion** : " + target.attrib['sslversion'] + "\n"
                if target.tag == "cipher" and target.attrib['strength'] not in ['acceptable', 'strong']:
                    title = "cipher" + " | " + target.attrib['sslversion']
                    description = "**Cipher** : " + target.attrib['cipher'] + "\n\n" + \
                                "**Status** : " + target.attrib['status'] + "\n\n" + \
                                "**strength** : " + target.attrib['strength'] + "\n\n" + \
                                "**sslversion** : " + target.attrib['sslversion'] + "\n"

                if title and description is not None:
                    dupe_key = hashlib.sha256(str(description + title).encode('utf-8')).hexdigest()
                    if dupe_key in dupes:
                        finding = dupes[dupe_key]
                        if finding.references:
                            finding.references = finding.references
                        dupes[dupe_key] = finding
                    else:
                        dupes[dupe_key] = True

                        finding = Finding(
                            title=title,
                            test=test,
                            description=description,
                            severity=severity,
                            dynamic_finding=True,)
                        finding.unsaved_endpoints = list()
                        dupes[dupe_key] = finding

                        if host:
                            if '://' in host:
                                endpoint = Endpoint.from_uri(host)
                            else:
                                endpoint = Endpoint(
                                    host=host,
                                    port=port)
                            finding.unsaved_endpoints.append(endpoint)
        return dupes.values()
