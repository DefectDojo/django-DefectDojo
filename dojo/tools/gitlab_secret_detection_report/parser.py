from enum import unique
import hashlib
import json
from dojo.models import Finding


class GitlabSecretDetectionReportParser(object):
    """
    GitLab's secret detection report
    See more: https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/blob/master/dist/secret-detection-report-format.json
    """

    def get_scan_types(self):
        return ["GitLab Secret Detection Report"]

    def get_label_for_scan_types(self, scan_type):
        return "GitLab Secret Detection Report"

    def get_description_for_scan_types(self, scan_type):
        return "GitLab Secret Detection Report file can be imported in JSON format (option --json)."

    def get_findings(self, file, test):
        # Load JSON data from uploaded file
        data = json.load(file)

        # Initial dataset to be deduplicate via JSON key
        dupes = dict()

        # This is required by schema - it won't be null / undefined
        date = data["scan"]["end_time"]

        # Vulnerabilities is stored on vulnerabilities key
        vulnerabilities = data["vulnerabilities"]
        for vulnerability in vulnerabilities:
            title = vulnerability["message"]
            description = vulnerability["description"]
            severity = self.normalise_severity(vulnerability["severity"])

            file_path = ""
            try:
                file_path = vulnerability["location"]["file"]
            except:
                pass

            line = -1
            try:
                line = int(vulnerability["location"]["start_line"])
            except:
                pass

            raw_source_code = ""
            try:
                raw_source_code = vulnerability["raw_source_code_extract"]
            except:
                pass

            finding = Finding(
                test=test,
                title=title,
                description=description,
                date=date,
                severity=severity,
                static_finding=True,
                dynamic_finding=False,
                unique_id_from_tool=vulnerabilities["id"]
            )

            if file_path != "":
                finding.file_path = file_path
            if line != -1:
                finding.line = line
            if raw_source_code != "":
                finding.description += "\n" + raw_source_code

            # internal de-duplication
            dupe_key = hashlib.sha256(
                str(description + title).encode("utf-8")
            ).hexdigest()
            if dupe_key in dupes:
                find = dupes[dupe_key]
                if finding.description:
                    find.description += "\n" + finding.description
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
