import json
import textwrap
from datetime import datetime

from dojo.models import Finding
from html2text import html2text


class AWSScout2Parser(object):
    # FIXME bad very bad
    item_data = ""
    pdepth = 0

    def get_scan_types(self):
        return ["AWS Scout2 Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "AWS Scout2 Scan"

    def get_description_for_scan_types(self, scan_type):
        return "JS file in scout2-report/inc-awsconfig/aws_config.js."

    def get_findings(self, filename, test):
        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        raw_data = content.replace("aws_info =", "")
        data = json.loads(raw_data)
        find_date = datetime.now()
        dupes = {}

        test_description = ""
        aws_account_id = data["aws_account_id"]
        test_description = "%s  **AWS Account:** %s\n" % (test_description, aws_account_id)
        last_run = data["last_run"]
        test_description = "%s  **Ruleset:** %s\n" % (test_description, last_run["ruleset_name"])
        test_description = "%s  **Ruleset Description:** %s\n" % (test_description, last_run["ruleset_about"])
        test_description = "%s  **Command:** %s\n" % (test_description, last_run["cmd"])

        # Summary for AWS Services
        test_description = "%s\n**AWS Services** \n\n" % (test_description)
        for service, items in list(last_run["summary"].items()):
            test_description = "%s\n**%s** \n" % (test_description, service.upper())
            test_description = "%s\n* **Checked Items:** %s\n" % (test_description, items["checked_items"])
            test_description = "%s* **Flagged Items:** %s\n" % (test_description, items["flagged_items"])
            test_description = "%s* **Max Level:** %s\n" % (test_description, items["max_level"])
            test_description = "%s* **Resource Count:** %s\n" % (test_description, items["resources_count"])
            test_description = "%s* **Rules Count:** %s\n\n" % (test_description, items["rules_count"])
        test.description = test_description
        test.save()

        scout2_findings = []

        # Configured AWS Services
        for service in list(data["services"].items()):
            for service_item in service:
                if "findings" in service_item:
                    for name, finding in list(service_item["findings"].items()):
                        if finding["items"]:
                            description_text = ""
                            for name in finding["items"]:
                                description_text = description_text + "**Location:** " + name + "\n\n---\n"
                                description_text = description_text + "\n"
                                key = name.split('.')
                                i = 1
                                lookup = service_item
                                while i < len(key):
                                    if key[i] in lookup:
                                        if (type(lookup[key[i]]) is dict):
                                            lookup = lookup[key[i]]
                                            if (key[i - 1] == "security_groups" or key[i - 1] == "PolicyDocument"):
                                                break
                                    i = i + 1

                                self.recursive_print(lookup)
                                description_text = description_text + self.item_data
                                self.item_data = ""

                            mobsf_item = {
                                "category": "Mobile Permissions",
                                "title": finding["description"],
                                "severity": finding["level"],
                                "description": description_text
                            }
                            scout2_findings.append(mobsf_item)

        for scout2_finding in scout2_findings:
            title = html2text(scout2_finding["title"])
            sev = self.getCriticalityRating(scout2_finding["severity"])
            description = scout2_finding["description"]
            dupe_key = sev + title
            if dupe_key in dupes:
                find = dupes[dupe_key]
                if description is not None:
                    find.description += description
            else:
                find = Finding(title=textwrap.shorten(title, 150),
                               cwe=1032,  # Security Configuration Weaknesses, would like to fine tune
                               test=test,
                               description="**AWS Account:** " + aws_account_id + "\n" + description,
                               severity=sev,
                               references=None,
                               date=find_date,
                               dynamic_finding=True)
                dupes[dupe_key] = find
        return list(dupes.values())

    def formatview(self, depth):
        if depth > 1:
            return "* "
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
    def getCriticalityRating(self, rating):
        criticality = "Info"
        if rating == "warning":
            criticality = "Medium"
        elif rating == "danger":
            criticality = "Critical"

        return criticality
