import json
from dojo.models import Finding
from dojo.tools.semgrep.models import SemgrepJSONResult


class SemgrepJSONParser(object):

    def __init__(self, filehandle, test):
        tree = self.parse_json(filehandle)

        self.items = []
        if tree:
            results = tree.get('results')

            if not results:
                return

            for item in results:
                title = item['check_id']
                f = SemgrepJSONResult(item['extra'], item['path'], item['start'], item['end'])

                findingItem = Finding(
                    title=f.title,
                    severity=f.severity,
                    numerical_severity=Finding.get_numerical_severity(f.severity),
                    description=f.message,
                    mitigation='N/A',
                    file_path=item['path'],
                    cwe=f.cwe,
                    line=f.start,
                    active=False,
                    verified=False,
                    url='N/A',
                    impact='N/A',
                    static_finding=True,
                    test=test
                )
                self.items.append(findingItem)

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
