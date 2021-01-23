import json
import hashlib
from dojo.models import Finding


class SecretsScannerJSONParser(object):
    """
    A class that can be used to parse the TJX secrets-scanner JSON report files
    """

    def __init__(self, filename, test):
        """
        Converts a secrest-scanner report to DefectDojo findings
        """

        self.dupes = dict()
        # Start with an empty findings
        self.items = ()
        # Exit if file is not provided
        if filename is None:
            return

        data = filename.read()

        for repo in self.parse_json(data):
            for commit in repo["commits"]:
                for leak in commit["leaks"]:
                    line = None
                    file_path = leak["file"]
                    reason = leak["type"]
                    titleText = reason + " discovered in: " + file_path
                    description = "**Commit Hash:** " + commit["hash"] + "\n"
                    description += "**Commit Date:** " + commit["date"] + "\n"
                    description += "**Commit URL:** " + leak["url"] + "\n"
                    description += "**Author:** " + commit["author"] + " <" + commit["email"] + ">" + "\n"
                    description += "**Reason:** " + reason + "\n"
                    description += "**Path:** " + file_path + "\n"
                    if "line" in leak:
                        description += "**Line:** %i\n" % leak["line"]
                        line = leak["line"]

                    severity = "High"
                    if "Github" in reason or "AWS" in reason or "Heroku" in reason or "Azure" in reason:
                        severity = "Critical"

                    dupe_key = hashlib.sha256((leak["url"]).encode("utf-8") + (leak["type"]).encode("utf-8") + str(leak["line"]).encode("utf-8")).hexdigest()

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
                                        line=line,
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
        return json_data["results"]
