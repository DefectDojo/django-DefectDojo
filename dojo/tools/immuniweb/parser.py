from xml.dom import NamespaceErr
import hashlib
import re
from urlparse import urlparse
from dojo.models import Endpoint, Finding
from defusedxml import ElementTree

__author__= 'properam'


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
            url = vulnerability.find("URL").text
            parseUrl = urlparse(url)
            print(parseUrl)

        return