import json
import hashlib
from urllib.parse import urlparse
from dojo.models import Endpoint, Finding

__author__ = 'dr3dd589'


class WpscanJSONParser(object):
    def __init__(self, file, test):
        self.dupes = dict()
        self.items = ()
        if file is None:
            return
        tree = json.load(file)
        for content in tree:
            node = tree[content]