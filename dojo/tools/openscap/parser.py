import StringIO
import hashlib
import lxml.etree as le
from dojo.models import Finding

__author__ = 'dr3dd589'

class OpenscapXMLParser(object):
    def __init__(self, file, test):
        self.dupes = dict()
        self.items = ()
        if file is None:
            return

        parser = le.XMLParser(resolve_entities=False)
        nscan = le.parse(file, parser)
        root = nscan.getroot()

        print("[+] : "+root.tag)   #remove after completion.

        if 'Benchmark' not in root.tag:
            raise NamespaceErr("This doesn't seem to be a valid Openscap vulnerability scan xml file.")

        