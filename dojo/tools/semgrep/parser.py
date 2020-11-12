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
                semgrep_result = SemgrepJSONResult(item['extra'], item['path'], item['start'], item['end'])

                findingItem = Finding(
                    title=semgrep_result.title,
                    severity=semgrep_result.severity,
                    numerical_severity=Finding.get_numerical_severity(semgrep_result.severity),
                    description=semgrep_result.message,
                    mitigation='N/A',
                    file_path=item['path'],
                    cwe=semgrep_result.cwe,
                    line=semgrep_result.start,
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
