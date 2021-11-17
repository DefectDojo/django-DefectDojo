import hashlib
import json
from datetime import datetime

from dojo.models import Finding  # , Endpoint

# from logging import critical
# from urllib.parse import urlparse


class CloudsploitParser(object):
    """
    AquaSecurity CloudSploit https://github.com/aquasecurity/cloudsploit
    """

    def get_scan_types(self):
        return ["Cloudsploit Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Cloudsploit Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Cloudsploit report file can be imported in JSON format (option --json)."

    def get_findings(self, file, test):
        data = json.load(file)
        find_date = datetime.now()
        dupes = dict()
        for item in data:
            title = item['title']
            if type(item['region']) is str:
                region = item['region']
            elif type(item['region']) is list:
                region = ','.join(item['region'])
            description = "**Finding** : " + item['message'] + "\n" + \
                "**Resource** : " + item['resource'] + "\n" + \
                "**Region** : " + region
            severity = self.convert_severity(item['status'])
            finding = Finding(
                title=title,
                test=test,
                description=description,
                component_name=item['resource'],
                severity=severity,
                impact=item['description'],
                date=find_date,
                dynamic_finding=True,
            )

            # internal de-duplication
            dupe_key = hashlib.sha256(str(description + title).encode('utf-8')).hexdigest()

            if dupe_key in dupes:
                find = dupes[dupe_key]
                if finding.description:
                    find.description += "\n" + finding.description
                dupes[dupe_key] = find
            else:
                dupes[dupe_key] = finding

        return list(dupes.values())

    def convert_severity(self, status):
        """Convert severity value"""
        if status == "WARN":
            return "Medium"
        if status == "FAIL":
            return "Critical"
        else:
            return "Info"
