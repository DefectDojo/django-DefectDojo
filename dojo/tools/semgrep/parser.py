from hashlib import md5
import json
from dojo.models import Finding
from .models import SemgrepJSONResult

class SemgrepJSONParser(object):
    def __init__(self, filehandle, test):
        tree = self.parse_json(filehandle)

        if tree:
            self.items = get_items(tree, test)
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
        dupes = dict()
        results = tree.get('results')

        if not results:
            return list()

        for finding in results():
            f = SemgrepJSONResult(finding)
            dupes[f.dedupe_key] = Finding(
                title = f.check_id
                severity = f.severity
                description = f.message
                mitigation = f.fix
                references = f.references
                file_path = f.path
                line = ' '.join([f.start, f.end])
                cve = None
                cwe = f.cwe
                active = True
                verified = False
                false_p = False
                duplicate = False
                out_of_scope = False
                impact = 'No impact provided'
                static_finding = True
                test = self.test
            )
            return list(dupes.values())