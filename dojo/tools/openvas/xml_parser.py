import csv
import hashlib
import io
from dateutil.parser import parse
from xml.dom import NamespaceErr
from defusedxml import ElementTree as ET
from dojo.models import Finding, Endpoint


class OpenVASXMLParser(object):
    def __init__(self) -> None:
        pass