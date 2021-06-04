import hashlib
import json
import textwrap
from dojo.models import Finding


class GitlabContainerScanParser(object):
    """
    GitLab's container scanning report
    See more: https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/blob/master/dist/container-scanning-report-format.json
    """

    def get_scan_types(self):
        return ["GitLab Container Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "GitLab Container Scan Scan"

    def get_description_for_scan_types(self, scan_type):
        return "GitLab Container Scan report file can be imported in JSON format (option --json)."

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

            component_name = ""
            component_version = ""
            try:
                dependency = vulnerability["location"]["dependency"]
                component_name = dependency["package"]["name"]
                component_version = dependency["version"]
            except:
                pass

            finding = Finding(
                title=title,
                date=date,
                test=test,
                description=description,
                severity=severity,
                static_finding=True,
                dynamic_finding=False,
            )

            # Add component fields if not empty
            for id in vulnerability["identifiers"]:
                if "type" in id:
                    if id.get("type") == "cve":
                        finding.cve = id["value"]
                    if id.get("type") == "cwe":
                        finding.cwe = id["value"]
            if component_name != "":
                finding.component_name = textwrap.shorten(
                    component_name, width=190, placeholder="..."
                )
            if component_version != "":
                finding.component_version = textwrap.shorten(
                    component_version, width=90, placeholder="..."
                )

            if "solution" in vulnerability:
                finding.mitigation = vulnerability["solution"]

            # internal de-duplication via description + title
            dupe_key = hashlib.sha256(
                str(description + title).encode("utf-8")
            ).hexdigest()
            if dupe_key in dupes:
                find = dupes[dupe_key]
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
