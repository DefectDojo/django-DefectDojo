
import json
from datetime import datetime

from html2text import html2text

from dojo.models import Finding


class MobSFParser(object):

    def get_scan_types(self):
        return ["MobSF Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "MobSF Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Export a JSON file using the API, api/v1/report_json."

    def get_findings(self, filename, test):
        tree = filename.read()
        try:
            data = json.loads(str(tree, 'utf-8'))
        except:
            data = json.loads(tree)
        find_date = datetime.now()
        dupes = {}
        test_description = ""
        if "name" in data:
            test_description = "**Info:**\n"
            if "packagename" in data:
                test_description = "%s  **Package Name:** %s\n" % (test_description, data["packagename"])

            if "mainactivity" in data:
                test_description = "%s  **Main Activity:** %s\n" % (test_description, data["mainactivity"])

            if "pltfm" in data:
                test_description = "%s  **Platform:** %s\n" % (test_description, data["pltfm"])

            if "sdk" in data:
                test_description = "%s  **SDK:** %s\n" % (test_description, data["sdk"])

            if "min" in data:
                test_description = "%s  **Min SDK:** %s\n" % (test_description, data["min"])

            if "targetsdk" in data:
                test_description = "%s  **Target SDK:** %s\n" % (test_description, data["targetsdk"])

            if "minsdk" in data:
                test_description = "%s  **Min SDK:** %s\n" % (test_description, data["minsdk"])

            if "maxsdk" in data:
                test_description = "%s  **Max SDK:** %s\n" % (test_description, data["maxsdk"])

            test_description = "%s\n**File Information:**\n" % (test_description)

            if "name" in data:
                test_description = "%s  **Name:** %s\n" % (test_description, data["name"])

            if "md5" in data:
                test_description = "%s  **MD5:** %s\n" % (test_description, data["md5"])

            if "sha1" in data:
                test_description = "%s  **SHA-1:** %s\n" % (test_description, data["sha1"])

            if "sha256" in data:
                test_description = "%s  **SHA-256:** %s\n" % (test_description, data["sha256"])

            if "size" in data:
                test_description = "%s  **Size:** %s\n" % (test_description, data["size"])

            if "urls" in data:
                curl = ""
                for url in data["urls"]:
                    for curl in url["urls"]:
                        curl = "%s\n" % (curl)

                if curl:
                    test_description = "%s\n**URL's:**\n %s\n" % (test_description, curl)

            if "bin_anal" in data:
                test_description = "%s  \n**Binary Analysis:** %s\n" % (test_description, data["bin_anal"])

        test.description = html2text(test_description)

        mobsf_findings = []
        # Mobile Permissions
        if "permissions" in data:
            # for permission, details in data["permissions"].items():
            if type(data["permissions"]) is list:
                for details in data["permissions"]:
                    mobsf_item = {
                        "category": "Mobile Permissions",
                        "title": details.get("name", ""),
                        "severity": self.getSeverityForPermission(details.get("status")),
                        "description": "**Permission Type:** " + details.get("name", "") + " (" + details.get("status", "") + ")\n\n**Description:** " + details.get("description", "") + "\n\n**Reason:** " + details.get("reason", ""),
                        "file_path": None
                    }
                    mobsf_findings.append(mobsf_item)
            else:
                for permission, details in list(data["permissions"].items()):
                    mobsf_item = {
                        "category": "Mobile Permissions",
                        "title": permission,
                        "severity": self.getSeverityForPermission(details.get("status", "")),
                        "description": "**Permission Type:** " + permission + "\n\n**Description:** " + details.get("description", ""),
                        "file_path": None
                    }
                    mobsf_findings.append(mobsf_item)

        # Insecure Connections
        if "insecure_connections" in data:
            for details in data["insecure_connections"]:
                insecure_urls = ""
                for url in details.split(','):
                    insecure_urls = insecure_urls + url + "\n"

                mobsf_item = {
                    "category": None,
                    "title": "Insecure Connections",
                    "severity": "Low",
                    "description": insecure_urls,
                    "file_path": None
                }
                mobsf_findings.append(mobsf_item)

        # Binary Analysis
        if "binary_analysis" in data:
            if type(data["binary_analysis"]) is list:
                for details in data["binary_analysis"]:
                    for binary_analysis_type in details:
                        if "name" != binary_analysis_type:
                            mobsf_item = {
                                "category": "Binary Analysis",
                                "title": details[binary_analysis_type]["description"].split(".")[0],
                                "severity": details[binary_analysis_type]["severity"].replace("warning", "low").title(),
                                "description": details[binary_analysis_type]["description"],
                                "file_path": details["name"]
                            }
                            mobsf_findings.append(mobsf_item)
            else:
                for binary_analysis_type, details in list(data["binary_analysis"].items()):
                    # "Binary makes use of insecure API(s)":{
                    #     "detailed_desc":"The binary may contain the following insecure API(s) _vsprintf.",
                    #     "severity":"high",
                    #     "cvss":6,
                    #     "cwe":"CWE-676 - Use of Potentially Dangerous Function",
                    #     "owasp-mobile":"M7: Client Code Quality",
                    #     "masvs":"MSTG-CODE-8"
                    # }
                    mobsf_item = {
                        "category": "Binary Analysis",
                        "title": details["detailed_desc"],
                        "severity": details["severity"].replace("good", "info").title(),
                        "description": details["detailed_desc"],
                        "file_path": None
                    }
                    mobsf_findings.append(mobsf_item)

        # specific node for Android reports
        if "android_api" in data:
            # "android_insecure_random": {
            #     "files": {
            #         "u/c/a/b/a/c.java": "9",
            #         "kotlinx/coroutines/repackaged/net/bytebuddy/utility/RandomString.java": "3",
            #         ...
            #         "hu/mycompany/vbnmqweq/gateway/msg/Response.java": "13"
            #     },
            #     "metadata": {
            #         "id": "android_insecure_random",
            #         "description": "The App uses an insecure Random Number Generator.",
            #         "type": "Regex",
            #         "pattern": "java\\.util\\.Random;",
            #         "severity": "high",
            #         "input_case": "exact",
            #         "cvss": 7.5,
            #         "cwe": "CWE-330 Use of Insufficiently Random Values",
            #         "owasp-mobile": "M5: Insufficient Cryptography",
            #         "masvs": "MSTG-CRYPTO-6"
            #     }
            # },
            for api, details in list(data["android_api"].items()):
                mobsf_item = {
                    "category": "Android API",
                    "title": details["metadata"]["description"],
                    "severity": details["metadata"]["severity"].replace("warning", "low").title(),
                    "description": "**API:** " + api + "\n\n**Description:** " + details["metadata"]["description"],
                    "file_path": None
                }
                mobsf_findings.append(mobsf_item)

        # Manifest
        if "manifest" in data:
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
        if "findings" in data:
            for title, finding in list(data["findings"].items()):
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
            title = mobsf_finding["title"]
            sev = self.getCriticalityRating(mobsf_finding["severity"])
            description = ""
            file_path = None
            if mobsf_finding["category"]:
                description += "**Category:** " + mobsf_finding["category"] + "\n\n"
            description = description + html2text(mobsf_finding["description"])
            finding = Finding(
                title=title,
                cwe=919,  # Weaknesses in Mobile Applications
                test=test,
                description=description,
                severity=sev,
                references=None,
                date=find_date,
                static_finding=True,
                dynamic_finding=False,
                nb_occurences=1,
            )
            if mobsf_finding["file_path"]:
                finding.file_path = mobsf_finding["file_path"]

            dupe_key = sev + title
            if dupe_key in dupes:
                find = dupes[dupe_key]
                if description is not None:
                    find.description += description
                find.nb_occurences += 1
            else:
                dupes[dupe_key] = finding
        return list(dupes.values())

    def getSeverityForPermission(self, status):
        """Convert status for permission detection to severity

        In MobSF there is only 4 know values for permission,
         we map them as this:
        dangerous         => High (Critical?)
        normal            => Info
        signature         => Info (it's positive so... Info)
        signatureOrSystem => Info (it's positive so... Info)
        """
        if "dangerous" == status:
            return "High"
        else:
            return "Info"

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
