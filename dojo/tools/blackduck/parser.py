import hashlib

from dojo.models import Finding
from .importer import BlackduckImporter


class BlackduckParser(object):
    """
    Can import as exported from Blackduck:
    - from a zip file containing a security.csv and files.csv
    - a single security.csv file
    """

    def get_scan_types(self):
        return ["Blackduck Hub Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Blackduck Hub Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Upload the zip file containing the security.csv and components.csv for Security and License risks."

    def get_findings(self, filename, test):
        normalized_findings = self.normalize_findings(filename)
        return self.ingest_findings(normalized_findings, test)

    def normalize_findings(self, filename):
        importer = BlackduckImporter()

        findings = sorted(importer.parse_findings(filename), key=lambda f: f.vuln_id)
        return findings

    def ingest_findings(self, normalized_findings, test):
        dupes = dict()
        for i in normalized_findings:
            vulnerability_id = i.vuln_id
            cwe = 0  # need a way to automaticall retrieve that see #1119
            title = self.format_title(i)
            description = self.format_description(i)
            severity = str(i.security_risk.title())
            mitigation = self.format_mitigation(i)
            impact = i.impact
            references = self.format_reference(i)

            dupe_key = hashlib.md5(
                "{} | {}".format(title, i.vuln_source).encode("utf-8")
            ).hexdigest()

            if dupe_key in dupes:
                finding = dupes[dupe_key]
                if finding.description:
                    finding.description += "Vulnerability ID: {}\n {}\n".format(
                        vulnerability_id, i.vuln_source
                    )
                dupes[dupe_key] = finding
            else:
                dupes[dupe_key] = True
                finding = Finding(
                    title=title,
                    cwe=int(cwe),
                    test=test,
                    description=description,
                    severity=severity,
                    mitigation=mitigation,
                    impact=impact,
                    references=references,
                    url=i.url,
                    file_path=i.locations,
                    component_name=i.component_name,
                    component_version=i.component_version,
                    static_finding=True,
                )
                if vulnerability_id:
                    finding.unsaved_vulnerability_ids = [vulnerability_id]

                dupes[dupe_key] = finding

        return dupes.values()

    def format_title(self, i):
        if i.channel_version_origin_id is not None:
            component_title = i.channel_version_origin_id
        else:
            component_title = i.component_origin_id

        return "{} - {}".format(i.vuln_id, component_title)

    def format_description(self, i):
        description = "Published on: {}\n\n".format(str(i.published_date))
        description += "Updated on: {}\n\n".format(str(i.updated_date))
        description += "Base score: {}\n\n".format(str(i.base_score))
        description += "Exploitability: {}\n\n".format(str(i.exploitability))
        description += "Description: {}\n".format(i.description)

        return description

    def format_mitigation(self, i):
        mitigation = "Remediation status: {}\n".format(i.remediation_status)
        mitigation += "Remediation target date: {}\n".format(i.remediation_target_date)
        mitigation += "Remediation actual date: {}\n".format(i.remediation_actual_date)
        mitigation += "Remediation comment: {}\n".format(i.remediation_comment)

        return mitigation

    def format_reference(self, i):
        reference = "Source: {}\n".format(i.vuln_source)
        reference += "URL: {}\n".format(i.url)

        return reference
