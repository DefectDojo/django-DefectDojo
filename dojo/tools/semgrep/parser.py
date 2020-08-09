from hashlib import md5
import json
from dojo.models import Finding
from .models import SemgrepJSONResult

class SemgrepJSONParser(object):
    def __init__(self, filehandle, test):
        tree = self.parse_json(filehandle)
        self.dupes = dict()

        if tree:
            self.items = list()
        else:
            self.items = list()

    def parse_json(self, filehandle):
        try:
            data = filehandle.read()
        except:
            return None

        try:
            tree = json.loads(data)
        except:
            raise Exception("Invalid format")

        return tree

    def get_items(self, tree, test):
        items = {}
        results = tree.get('results')

        if not results:
            return list()

        for finding in results():
            item = get_item(finding)


def get_item(finding, test):
    f = SemgrepJSONResult(finding)

    return Finding(
        static_finding = True
        title = None
        severity = f.severity
        description = f.message
        mitigation = f.fix
        references = f.references
        file_path = f.path
        line = f.start + f.end
        cve = None
        cwe = f.cwe
        active = True
        verified = False
        false_p = False
        duplicate = False
        out_of_scope = False
        impact = None
        test = self.test
    )