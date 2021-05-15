
import re
from datetime import datetime
import sys
import io
import csv
import textwrap

from dojo.models import Finding


class AWSProwlerParser(object):

    def get_scan_types(self):
        return ["AWS Prowler Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "AWS Prowler Scan"

    def get_description_for_scan_types(self, scan_type):
        return "AWS Security Hub exports in JSON format."

    def get_findings(self, filename, test):
        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        csv.field_size_limit(int(sys.maxsize / 10))  # the request/resp are big
        reader = csv.DictReader(io.StringIO(content))
        dupes = dict()

        find_date = datetime.now()
        account = None

        for row in reader:
            profile = row.get('PROFILE')
            account = row.get('ACCOUNT_NUM')
            region = row.get('REGION')
            title_id = row.get('TITLE_ID')
            result = row.get('RESULT', row.get('CHECK_RESULT'))
            scored = row.get('SCORED')
            level = row.get('LEVEL')
            severity = row.get('SEVERITY')
            title_text = row.get('TITLE_TEXT')
            # remove '[check000] ' at the start of each title
            title_text = re.sub(r'\[.*\]\s', '', title_text)
            notes = row.get('NOTES')

            sev = self.getCriticalityRating(result, level, severity)
            description = "**Region:** " + region + "\n\n" + str(notes) + "\n"

            if result == "INFO" or result == "PASS":
                active = False
            else:
                active = True

            dupe_key = sev + title_text
            if dupe_key in dupes:
                find = dupes[dupe_key]
                if description is not None:
                    find.description += description + "\n\n"
                find.nb_occurences += 1
            else:
                find = Finding(
                    active=active,
                    title=textwrap.shorten(title_text, 150),
                    cwe=1032,  # Security Configuration Weaknesses, would like to fine tune
                    test=test,
                    description="**AWS Account:** " + str(account) + "\n**Control:** " + str(title_text) + "\n**CIS Control:** " + str(title_id) + ", " + str(level) + "\n\n" + description,
                    severity=sev,
                    references=None,
                    date=find_date,
                    dynamic_finding=True,
                    nb_occurences=1,
                )
                dupes[dupe_key] = find

        return list(dupes.values())

    def formatview(self, depth):
        if depth > 1:
            return "* "
        else:
            return ""

    # Criticality rating
    def getCriticalityRating(self, result, level, severity):
        criticality = "Info"
        if result == "INFO" or result == "PASS":
            criticality = "Info"
        elif result == "FAIL":
            if severity:
                return severity
            else:
                if level == "Level 1":
                    criticality = "Critical"
                else:
                    criticality = "High"

        return criticality
