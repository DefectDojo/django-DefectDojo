from xml.dom import NamespaceErr
import hashlib
from defusedxml import ElementTree as ET
from urllib.parse import urlparse
from dojo.models import Endpoint, Finding


__author__ = 'dr3dd589'


WEAK_CIPHER_LIST = [
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"
]

PROTOCOLS = [
    "sslv2",
    "sslv3",
    "tlsv1",
    "tlsv1_1",
    "tlsv1_2",
    "tlsv1_3"
]


class SslyzeXmlParser(object):

    def __init__(self, file, test):
        self.dupes = dict()
        self.items = ()
        if file is None:
            return

        tree = ET.parse(file)
        # get root of tree.
        root = tree.getroot()
        if 'document' not in root.tag:
            raise NamespaceErr("This doesn't seem to be a valid sslyze xml file.")

        results = root.find('results')
        for target in results:
            url = target.attrib['host']
            port = target.attrib['port']
            parsedUrl = urlparse(url)
            protocol = parsedUrl.scheme
            query = parsedUrl.query
            fragment = parsedUrl.fragment
            path = parsedUrl.path
            try:
                (host, port) = parsedUrl.netloc.split(':')
            except:
                host = parsedUrl.netloc
            for element in target:
                title = ""
                severity = ""
                description = ""
                severity = "Info"
                weak_cipher = {}
                if element.tag == 'heartbleed':
                    heartbleed_element = element.find('openSslHeartbleed')
                    if 'isVulnerable' in heartbleed_element.attrib:
                        if heartbleed_element.attrib['isVulnerable'] == 'True':
                            title = element.attrib['title'] + " | " + url
                            description = "**heartbleed** : Vulnerable" + "\n\n" + \
                                        "**title** : " + element.attrib['title']
                if element.tag == 'openssl_ccs':
                    openssl_ccs_element = element.find('openSslCcsInjection')
                    if 'isVulnerable' in openssl_ccs_element.attrib:
                        if openssl_ccs_element.attrib['isVulnerable'] == 'True':
                            title = element.attrib['title'] + " | " + url
                            description = "**openssl_ccs** : Vulnerable" + "\n\n" + \
                                        "**title** : " + element.attrib['title']
                if element.tag == 'reneg':
                    reneg_element = element.find('sessionRenegotiation')
                    if 'isSecure' in reneg_element.attrib:
                        if reneg_element.attrib['isSecure'] == 'False':
                            title = element.attrib['title'] + " | " + url
                            description = "**Session Renegotiation** : Vulnerable" + "\n\n" + \
                                        "**title** : " + element.attrib['title']
                if element.tag in PROTOCOLS and element.attrib['isProtocolSupported'] == "True":
                    weak_cipher[element.tag] = []
                    for ciphers in element:
                        if ciphers.tag == 'preferredCipherSuite' or ciphers.tag == 'acceptedCipherSuites':
                            for cipher in ciphers:
                                if cipher.attrib['name'] in WEAK_CIPHER_LIST:
                                    if not cipher.attrib['name'] in weak_cipher[element.tag]:
                                        weak_cipher[element.tag].append(cipher.attrib['name'])
                    if len(weak_cipher[element.tag]) > 0:
                        title = element.tag + " | " + "Weak Ciphers" + " | " + url
                        description = "**Protocol** : " + element.tag + "\n\n" + \
                                    "**Weak Ciphers** : " + ",\n\n".join(weak_cipher[element.tag])
                if title and description is not None:
                    dupe_key = hashlib.md5(str(description + title).encode('utf-8')).hexdigest()
                    if dupe_key in self.dupes:
                        finding = self.dupes[dupe_key]
                        if finding.references:
                            finding.references = finding.references
                        self.dupes[dupe_key] = finding
                    else:
                        self.dupes[dupe_key] = True

                        finding = Finding(
                            title=title,
                            test=test,
                            active=False,
                            verified=False,
                            description=description,
                            severity=severity,
                            numerical_severity=Finding.get_numerical_severity(severity),
                            dynamic_finding=True,)
                        finding.unsaved_endpoints = list()
                        self.dupes[dupe_key] = finding

                        if url is not None:
                            finding.unsaved_endpoints.append(Endpoint(
                                host=host,
                                port=port,
                                path=path,
                                protocol=protocol,
                                query=query,
                                fragment=fragment,))
                self.items = self.dupes.values()
