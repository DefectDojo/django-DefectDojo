import json
import logging

from dojo.models import Finding

logger = logging.getLogger(__name__)


class DevSkimParser(object):
    def _convert_devskim_severity_to_dojo_severity(self, dependency_track_severity):
        severity = dependency_track_severity
        if severity == 1:
            return "Critical"
        elif severity == 2:
            return "High"
        elif severity == 4:
            return "Medium"
        elif severity == 8:
            return "Low"
        elif severity == 16:
            return "Informational"
        else:
            return None

    def __init__(self, filename, test):
        tree = filename.read()
        try:
            data = json.loads(str(tree, 'utf-8'))
        except:
            data = json.loads(tree)
        dupes = dict()

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

            title = "Rule: " + item["rule_name"] + " Rule ID: " + item["rule_id"]

            #  ##### Finding details information ######
            findingdetail += item['description']
            findingdetail += "\nMatch:\n"
            findingdetail += item["match"] + "\n"

            sev = item["severity"]

            dupe_key = item["rule_id"] + item["filename"] + str(item["start_line"]) + str(item["start_column"])

            vulnerability_severity = self._convert_devskim_severity_to_dojo_severity(item["severity"])


            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                dupes[dupe_key] = True

                find = Finding(title=title,
                               active=True,
                               verified=False,
                               description=findingdetail,
                               severity=vulnerability_severity,
                               numerical_severity=Finding.get_numerical_severity(vulnerability_severity),
                               impact=impact,
                               references=references,
                               file_path=item["filename"],
                               line=item["start_line"],
                               url='N/A',
                               static_finding=True)

                dupes[dupe_key] = find
                findingdetail = ''

        self.items = list(dupes.values())

