__author__ = 'aaronweaver'

from datetime import datetime
import json
from dojo.models import Finding


class ESLintParser(object):
    def _convert_eslint_severity_to_dojo_severity(self, eslint_severity):
        """
        Converts a Dependency Track severity to a DefectDojo severity.
        :param dependency_track_severity: The severity from Dependency Track
        :return: A DefectDojo severity if a mapping can be found; otherwise a null value is returned
        """
        severity = dependency_track_severity.lower()
        if severity == 2:
            return "High"
        elif severity == 1:
            return "Medium"
        else:
            return None

    def __init__(self, filename, test):
        tree = filename.read()
        try:
            data = json.loads(str(tree, 'utf-8'))
        except:
            data = json.loads(tree)

        for item in data:
            categories = ''
            language = ''
            mitigation = ''
            impact = ''
            references = ''
            findingdetail = ''
            title = ''
            group = ''
            status = ''

            if (len(item.messages) == 0):
                continue

            for message in item.messages:
                title = message["message"] + " Test ID: " + message["ruleId"]

                #  ##### Finding details information ######
                findingdetail += "Filename: " + item["filePath"] + "\n"
                findingdetail += "Line number: " + str(message["line"]) + "\n"

                sev = _convert_eslint_severity_to_dojo_severity(item["issue_severity"])
                mitigation = message["severity"]
                

                find = Finding(title=title,
                            test=test,
                            active=False,
                            verified=False,
                            description=findingdetail,
                            severity=sev.title(),
                            numerical_severity=Finding.get_numerical_severity(sev),
                            file_path=item["filePath"],
                            line=message["line"],
                            url='N/A',
                            static_finding=True)


        self.items = list(dupes.values())
