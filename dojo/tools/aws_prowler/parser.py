__author__ = 'Aaron Weaver'

from dojo.models import Finding
from datetime import datetime
import pandas as pd
import re
from django.utils.text import Truncator


class AWSProwlerParser(object):
    item_data = ""
    pdepth = 0

    def __init__(self, filename, test):
        find_date = datetime.now()
        dupes = {}

        df = pd.read_csv(filename, header=0, error_bad_lines=False)

        for i, row in df.iterrows():
            profile = df.ix[i, 'PROFILE']
            account = df.ix[i, 'ACCOUNT_NUM']
            region = df.ix[i, 'REGION']
            title_id = df.ix[i, 'TITLE_ID']
            result = df.ix[i, 'RESULT']
            scored = df.ix[i, 'SCORED']
            level = df.ix[i, 'LEVEL']
            title_text = df.ix[i, 'TITLE_TEXT']
            title_text = re.sub(r'\[.*\]\s', '', title_text)
            title_text_trunc = Truncator(title_text).words(8)
            notes = df.ix[i, 'NOTES']

            sev = self.getCriticalityRating(result, level)
            description = "**Region:** " + region + "\n\n" + notes + "\n"
            dupe_key = sev + title_text
            if dupe_key in dupes:
                find = dupes[dupe_key]
                if description is not None:
                    find.description += description + "\n\n"
            else:
                find = Finding(title=title_text_trunc,
                               cwe=1032,  # Security Configuration Weaknesses, would like to fine tune
                               test=test,
                               active=False,
                               verified=False,
                               description="**AWS Account:** " + str(account) + "\n**Control:** " + title_text + "\n**CIS Control:** " + str(title_id) + ", " + level + "\n\n" + description,
                               severity=sev,
                               numerical_severity=Finding.get_numerical_severity(sev),
                               references=None,
                               date=find_date,
                               dynamic_finding=True)
                dupes[dupe_key] = find
        self.items = list(dupes.values())

        if account:
            test_description = ""
            test_description = "%s\n* **AWS Account:** %s\n" % (test_description, str(account))
            test.description = test_description
            test.save()

    def formatview(self, depth):
        if depth > 1:
            return "* "
            print("depth hit")
        else:
            return ""

    def recursive_print(self, src, depth=0, key=''):
        tabs = lambda n: ' ' * n * 2
        if isinstance(src, dict):
            for key, value in src.items():
                if isinstance(src, str):
                    self.item_data = self.item_data + key + "\n"
                self.recursive_print(value, depth + 1, key)
        elif isinstance(src, list):
            for litem in src:
                self.recursive_print(litem, depth + 2)
        else:
            if self.pdepth != depth:
                self.item_data = self.item_data + "\n"
            if key:
                self.item_data = self.item_data + self.formatview(depth) + '**%s:** %s\n\n' % (key.title(), src)
            else:
                self.item_data = self.item_data + self.formatview(depth) + '%s\n' % src
            self.pdepth = depth

    # Criticality rating
    def getCriticalityRating(self, result, level):
        criticality = "Info"
        if result == "INFO" or result == "PASS":
            criticality = "Info"
        elif result == "FAIL":
            if level == "Level 1":
                criticality = "Critical"
            else:
                criticality = "High"

        return criticality
