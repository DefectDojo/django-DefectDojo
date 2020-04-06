import json
import hashlib
from dojo.models import Finding


class GitleaksJSONParser(object):
    """
    A class that can be used to parse the Gitleaks JSON report files
    """

    def __init__(self, filename, test):
        """
        Converts a Gitleaks report to DefectDojo findings
        """

        self.dupes = dict()
        # Start with an empty findings
        self.items = ()
        # Exit if file is not provided
        if filename is None:
            return

        data = filename.read()

        for issue in self.parse_json(data):
            file_path = issue["file"]
            reason = issue["rule"]
            titleText = "Hard Coded " + reason + " in: " + file_path
            description = "**Commit:** " + issue["commitMessage"].rstrip("\n") + "\n"
            description += "**Commit Hash:** " + issue["commit"] + "\n"
            description += "**Commit Date:** " + issue["date"] + "\n"
            description += "**Author:** " + issue["author"] + " <" + issue["email"] + ">" + "\n"
            description += "**Reason:** " + reason + "\n"
            description += "**Path:** " + file_path + "\n"
            description += "\n**String Found:**\n" + issue["line"] + "\n"

            severity = "High"
            if "Github" in reason or "AWS" in reason or "Heroku" in reason:
                severity = "Critical"

            dupe_key = hashlib.md5((file_path + issue["line"] + issue["commit"]).encode("utf-8")).hexdigest()

            if dupe_key not in self.dupes:
                self.dupes[dupe_key] = Finding(title=titleText,
                                  test=test,
                                  cwe=798,
                                  active=False,
                                  verified=False,
                                  description=description,
                                  severity=severity,
                                  numerical_severity=Finding.get_numerical_severity(severity),
                                  mitigation="Secrets and passwords should be stored in a secure vault and/or secure storage.",
                                  impact="This weakness can lead to the exposure of resources or functionality to unintended actors, possibly providing attackers with sensitive information or even execute arbitrary code.",
                                  file_path=file_path,
                                  dynamic_finding=False,
                                  static_finding=True)
        self.items = list(self.dupes.values())

    def parse_json(self, json_output):
        # Load json data from the report file
        try:
            try:
                json_data = json.loads(str(json_output, 'utf-8'))
            except:
                json_data = json.loads(json_output)
        except ValueError:
            raise Exception("Invalid format")
        return json_data
