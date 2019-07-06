from xml.dom import NamespaceErr
import hashlib
from urllib.parse import urlparse
import re
from defusedxml import ElementTree as ET
from dojo.models import Endpoint, Finding

__author__ = 'dr3dd589'


class SslscanXMLParser(object):
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