import hashlib
import json
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
        date = data['scan']['end_time']

        # Vulnerabilities is stored on vulnerabilities key
        vulnerabilities = data['vulnerabilities']
        for vulnerability in vulnerabilities:
            # node = data[vulnerability]
            # if not node['pass']:
            title = vulnerability['message']
            description = vulnerability['description']
            severity = self.normalise_severity(vulnerability['severity'])

            # Get CVE & CWE
            cve = ""
            cwe = ""
            for id in vulnerability['identifiers']:
                try:
                    if id['type'] == "cve":
                        cve = id['value']
                    if id['type'] == "cwe":
                        cwe = id['value']
                except:
                    pass

            component_name = ""
            component_version = ""
            try:
                component_name = vulnerability['location']['dependency']['package']['name']
                component_version = vulnerability['location']['dependency']['version']
            except:
                pass

            solution = ""
            try:
                solution = vulnerability["solution"]
            except:
                pass

            finding = Finding(
                title=title,
                date=date,
                test=test,
                description=description,
                severity=severity,
                cve=cve,
                cwe=cwe,
                static_finding=True,
                dynamic_finding=False,
            )

            # Add component fields if not empty
            if component_name != "":
                finding.component_name = component_name[:190] + (component_name[190:] and '...')
            if component_version != "":
                finding.component_version = component_version[:90] + (component_version[90:] and '...')

            # Add mitigation if possible
            if solution != "":
                finding.mitigation = solution

            # internal de-duplication via description + title
            dupe_key = hashlib.sha256(str(description + title).encode('utf-8')).hexdigest()
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
        (Critical, High, Medium, Low, Unknown, Info) -> (Critical, High, Medium, Low, Informational)
        """
        if severity == "Unknown" or severity == "Info":
            return "Informational"
        return severity
