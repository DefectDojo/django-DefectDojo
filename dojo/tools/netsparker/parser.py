import json
import re
from dojo.models import Finding

__author__ = "Roy Shoemake"
__status__ = "Development"


# Function to remove HTML tags
TAG_RE = re.compile(r'<[^>]+>')


def cleantags(text):
    return TAG_RE.sub('', text)


class NetsparkerParser(object):
    def __init__(self, filename, test):
        data = json.load(filename)
        dupes = dict()

        for item in data["Vulnerabilities"]:
            categories = ''
            language = ''
            mitigation = ''
            impact = ''
            references = ''
            findingdetail = ''
            title = ''
            group = ''
            status = ''

            title = item["Name"]
            findingdetail = cleantags(item["Description"])
            cwe = item["Classification"]["Cwe"]
            sev = item["Severity"]
            if sev not in ['Info', 'Low', 'Medium', 'High', 'Critical']:
                sev = 'Info'
            mitigation = cleantags(item["RemedialProcedure"])
            references = cleantags(item["RemedyReferences"])
            url = item["Url"]
            impact = cleantags(item["Impact"])
            dupe_key = title + item["Name"] + item["Url"]

            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                dupes[dupe_key] = True

                find = Finding(title=title,
                               test=test,
                               active=False,
                               verified=False,
                               description=findingdetail,
                               severity=sev.title(),
                               numerical_severity=Finding.get_numerical_severity(sev),
                               mitigation=mitigation,
                               impact=impact,
                               references=references,
                               url=url,
                               cwe=cwe,
                               static_finding=True)
                dupes[dupe_key] = find
                findingdetail = ''

        self.items = dupes.values()
