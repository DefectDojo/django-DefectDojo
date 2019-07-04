from xml.dom import NamespaceErr
import hashlib
try:
    from lxml import etree as ET
except ImportError:
    import xml.etree.ElementTree as ET
import re

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


class SslyzeXmlParser(object):

    def __init__(self, file, test):
        self.dupes = dict()
        self.items = ()
        if file is None:
            return

        self.tree = ET.parse(file)
        # get root of tree.
        self.root = self.tree.getroot()
        if 'document' not in self.root.tag:
            raise NamespaceErr("This doesn't seem to be a valid sslyze xml file.")

        targets = get_target(self.tree)
        for target in targets:
                    

    def get_target(self, tree):
        return tree.xpath('//target')
                
    def get_hostname_validation(self, tree):
        return tree.xpath('//hostnameValidation')

    def get_protocol_name(self, tree):
        protocol_supported = []
        protocols = []
        protocols.append(tree.xpath('//sslv2'))
        protocols.append(tree.xpath('//sslv3'))
        protocols.append(tree.xpath('//tlsv1'))
        protocols.append(tree.xpath('//tlsv1_1'))
        protocols.append(tree.xpath('//tlsv1_2'))
        protocols.append(tree.xpath('//tlsv1_3'))

        for protocol in protocols:
            if protocol[0].attrib['isProtocolSupported'] == "True":
                protocol_supported.append(protocol[0])

        return protocol_supported

    def get_weak_cipher_suite(self, tree):
        protocols = self.get_protocol_name(tree)
        weak_cipher = {}

        for protocol in protocols:
            weak_cipher[protocol.tag] = []
            for ciphers in protocol:
                if ciphers.tag == 'preferredCipherSuite' or ciphers.tag == 'acceptedCipherSuites':
                    for cipher in ciphers:
                        if cipher.attrib['name'] in WEAK_CIPHER_LIST:
                            if not cipher.attrib['name'] in weak_cipher[protocol.tag]:
                                weak_cipher[protocol.tag].append(cipher.attrib['name'])
                            
        return weak_cipher

    def get_heartbleed(self, tree):
        return tree.xpath('//heartbleed')

    def get_openssl_ccs(self, tree):
        return tree.xpath('//openssl_ccs')