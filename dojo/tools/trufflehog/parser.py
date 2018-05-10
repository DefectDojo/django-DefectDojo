import json
import io
import hashlib
from dojo.models import Finding, Endpoint
from django.utils.encoding import smart_text, force_str

class TruffleHogJSONParser(object):
    def __init__(self, filename, test):

        data = filename.read()
        self.dupes = dict()
        self.items = ()

        for line in data.splitlines():
            json_data = self.parse_json(line)
            file = json_data["path"]
            titleText = "Hard Coded Credential(s) or Secret(s) in: " + file
            reason = json_data["reason"]


            commit = json_data["commit"]
            description = "**Commit:** " + commit.rstrip("\n") + "\n"
            description += "**Commit Hash:** " + json_data["commitHash"] + "\n"
            description += "**Commit Date:** " + json_data["date"] + "\n"
            description += "**Branch:** " + json_data["branch"] + "\n"
            description += "**Reason:** " + json_data["reason"] + "\n"
            description += "**Path:** " + file + "\n"

            severity = "Info"

            strings_found = ""

            for string in json_data["stringsFound"]:
                    strings_found += string + "\n"

            dupe_key = file
            description += "\n**Strings Found:**\n" + strings_found + "\n"

            if dupe_key in self.dupes:
                finding = self.dupes[dupe_key]
                finding.description = finding.description + description
                self.dupes[dupe_key] = finding
            else:
                self.dupes[dupe_key] = True

                finding = Finding(title=titleText,
                               test=test,
                               cwe=798,
                               active=False,
                               verified=False,
                               description=description,
                               severity=severity,
                               numerical_severity=Finding.get_numerical_severity(severity),
                               mitigation="Secrets and passwords should be stored in a secure vault and/or secure storage.",
                               impact="This weakness can lead to the exposure of resources or functionality to unintended actors, possibly providing attackers with sensitive information or even execute arbitrary code.",
                               references="N/A",
                               file_path=file,
                               url='N/A',
                               dynamic_finding=False,
                               static_finding=True)

                key = hashlib.md5(file).hexdigest()
                self.dupes[dupe_key] = finding

        self.items = self.dupes.values()

    def parse_json(self, json_output):
        try:
            json_data = json.loads(json_output)
        except:
            raise Exception("Invalid format")

        return json_data
