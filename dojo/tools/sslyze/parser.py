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

        tree = ET.parse(file)
        # get root of tree.
        root = tree.getroot()
        if 'document' not in root.tag:
            raise NamespaceErr("This doesn't seem to be a valid sslyze xml file.")