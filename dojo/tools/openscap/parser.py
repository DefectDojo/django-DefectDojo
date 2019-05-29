from xml.dom import NamespaceErr
import StringIO
import hashlib
import re
from defusedxml import ElementTree as ET
from dojo.models import Endpoint, Finding

__author__ = 'dr3dd589'

class OpenscapXMLParser(object):
    def __init__(self, file, test):
        self.dupes = dict()
        self.items = ()
        if file is None:
            return

        tree = ET.parse(file)
        root = tree.getroot()
        namespace = get_namespace(root)
        test_result = tree.find('./{0}TestResult'.format(namespace))

        print("[+] : "+root.tag)   #remove after completion.

        if 'Benchmark' not in root.tag:
            raise NamespaceErr("This doesn't seem to be a valid Openscap vulnerability scan xml file.")

    
    def get_namespace(element):
        m = re.match('\{.*\}', element.tag)
        return m.group(0) if m else ''