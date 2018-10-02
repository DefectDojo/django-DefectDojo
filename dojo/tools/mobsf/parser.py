__author__ = 'Aaron Weaver'

from dojo.models import Finding
from datetime import datetime
import json
from django.utils.text import Truncator
from django.utils.html import strip_tags


class MobSFParser(object):
    def __init__(self, filename, test):
        data = json.load(filename)
        find_date = datetime.now()
        dupes = {}
        test_description = ""
        if "name" in data:
            test_description = "**Info:**\n"
            test_description = "%s  **Package Name:** %s\n" % (test_description, data["packagename"])
            test_description = "%s  **Main Activity:** %s\n" % (test_description, data["mainactivity"])
            test_description = "%s  **Target SDK:** %s\n" % (test_description, data["targetsdk"])
            test_description = "%s  **Min SDK:** %s\n" % (test_description, data["minsdk"])
            test_description = "%s  **Max SDK:** %s\n" % (test_description, data["maxsdk"])

            test_description = "%s\n**File Information:**\n" % (test_description)
            test_description = "%s  **Name:** %s\n" % (test_description, data["name"])
            test_description = "%s  **Size:** %s\n" % (test_description, data["size"])
            test_description = "%s  **MD5:** %s\n" % (test_description, data["md5"])
            test_description = "%s  **SHA-1:** %s\n" % (test_description, data["sha1"])
            test_description = "%s  **SHA-256:** %s\n" % (test_description, data["sha256"])
            test_description = "%s  **Size:** %s\n" % (test_description, data["size"])

            curl = ""
            for url in data["urls"]:
                for curl in url["urls"]:
                    curl = "%s\n" % (curl)

            if curl:
                test_description = "%s\n**URL's:**\n %s\n" % (test_description, curl)

        test.description = test_description
        test.save()

        mobsf_findings = []
        # Mobile Permissions
        for permission, details in data["permissions"].items():
            mobsf_item = {
                "category": "Mobile Permissions",
                "title": permission,
                "severity": "info",
                "description": "Permission Type: " + details["status"] + "\n\n" + details["description"],
                "file_path": None
            }
            mobsf_findings.append(mobsf_item)

        # Binary Analysis
        for details in data["binary_analysis"]:
            mobsf_item = {
                "category": "Binary Analysis",
                "title": details["title"],
                "severity": details["stat"],
                "description": details["desc"],
                "file_path": details["file"]
            }
            mobsf_findings.append(mobsf_item)

        # Manifest
        for details in data["manifest"]:
            mobsf_item = {
                "category": "Manifest",
                "title": details["title"],
                "severity": details["stat"],
                "description": details["desc"],
                "file_path": None
            }
            mobsf_findings.append(mobsf_item)

        # MobSF Findings
        for title, finding in data["findings"].items():
            description = title
            file_path = None

            if "path" in finding:
                description = description + "\n\n**Files:**\n"
                for path in finding["path"]:
                    if file_path is None:
                        file_path = path
                    description = description + " * " + path + "\n"

            mobsf_item = {
                "category": "Findings",
                "title": title,
                "severity": finding["level"],
                "description": description,
                "file_path": file_path
            }

            mobsf_findings.append(mobsf_item)

        for mobsf_finding in mobsf_findings:
            title = strip_tags(mobsf_finding["title"])
            sev = self.getCriticalityRating(mobsf_finding["severity"])
            description = "Category: " + mobsf_finding["category"] + "\n\n" + strip_tags(mobsf_finding["description"])
            file_path = mobsf_finding["file_path"]
            dupe_key = sev + title
            if dupe_key in dupes:
                find = dupes[dupe_key]
                if description is not None:
                    find.description += description
            else:
                find = Finding(title=Truncator(title).words(5),
                               cwe=919,  # Weaknesses in Mobile Applications
                               test=test,
                               active=False,
                               verified=False,
                               description=description,
                               severity=sev,
                               numerical_severity=Finding.get_numerical_severity(sev),
                               references=None,
                               date=find_date,
                               file_path=file_path,
                               static_finding=True)
                dupes[dupe_key] = find
        self.items = dupes.values()

    # Criticality rating
    def getCriticalityRating(self, rating):
        criticality = "Info"
        if rating == "warning":
            criticality = "Info"
        else:
            criticality = rating.capitalize()

        return criticality

    def suite_data(self, suites):
        suite_info = ""
        suite_info += suites["name"] + "\n"
        suite_info += "Cipher Strength: " + str(suites["cipherStrength"]) + "\n"
        if "ecdhBits" in suites:
            suite_info += "ecdhBits: " + str(suites["ecdhBits"]) + "\n"
        if "ecdhStrength" in suites:
            suite_info += "ecdhStrength: " + str(suites["ecdhStrength"])
        suite_info += "\n\n"
        return suite_info
