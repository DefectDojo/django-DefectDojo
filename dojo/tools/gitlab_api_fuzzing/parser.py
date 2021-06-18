import hashlib
import json
from urllib.parse import urlparse
from dojo.models import Endpoint, Finding


class GitlabAPIFuzzingParser(object):
    """
    GitLab API Fuzzing Report

    Ref: https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/blob/master/dist/coverage-fuzzing-report-format.json
    """

    def get_scan_types(self):
        return ["GitLab API Fuzzing Report Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "GitLab API Fuzzing Report Scan"

    def get_description_for_scan_types(self, scan_type):
        return "GitLab API Fuzzing Report report file can be imported in JSON format (option --json)."

    def get_findings(self, file, test):
        data = json.load(file)

        dupes = dict()

        vulnerabilities = data["vulnerabilities"]
        for vulnerability in vulnerabilities:

            title = vulnerability["name"]
            severity = self.normalise_severity(vulnerability["severity"])

            description = vulnerability["category"]
            try:
                location = vulnerability["location"]
                description += "\n" + location["crash_type"]
                description += "\n" + location["crash_state"]
            except:
                pass

            finding = Finding(
                title=title,
                test=test,
                description=description,
                severity=severity,
                static_finding=False,
                dynamic_finding=True,
            )

            # internal de-duplication
            dupe_key = hashlib.sha256(
                str(description + title).encode("utf-8")
            ).hexdigest()
            if dupe_key in dupes:
                find = dupes[dupe_key]
                # appending description(s) from the similar findings
                if finding.description:
                    find.description += "\n\n-----\n\n" + finding.description
                find.unsaved_endpoints.extend(finding.unsaved_endpoints)
                dupes[dupe_key] = find
            else:
                dupes[dupe_key] = finding

        return list(dupes.values())

    def normalise_severity(self, severity):
        """
        Normalise GitLab's severity to DefectDojo's
        (Critical, High, Medium, Low, Unknown, Info) -> (Critical, High, Medium, Low, Info)
        """
        if severity == "Unknown":
            return "Info"
        return severity
