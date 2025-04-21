import hashlib

from dojo.models import Finding

from .importer import BlackduckImporter


class BlackduckParser:

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

        return sorted(
            importer.parse_findings(filename), key=lambda f: f.vuln_id,
        )

    def ingest_findings(self, normalized_findings, test):
        dupes = {}
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
                f"{title} | {i.vuln_source}".encode(),
            ).hexdigest()

            if dupe_key in dupes:
                finding = dupes[dupe_key]
                if finding.description:
                    finding.description += (
                        f"Vulnerability ID: {vulnerability_id}\n {i.vuln_source}\n"
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

        return list(dupes.values())

    def format_title(self, i):
        if i.channel_version_origin_id is not None:
            component_title = i.channel_version_origin_id
        else:
            component_title = i.component_origin_id

        return f"{i.vuln_id} - {component_title}"

    def format_description(self, i):
        description = f"Published on: {i.published_date}\n\n"
        description += f"Updated on: {i.updated_date}\n\n"
        description += f"Base score: {i.base_score}\n\n"
        description += f"Exploitability: {i.exploitability}\n\n"
        description += f"Description: {i.description}\n"

        return description

    def format_mitigation(self, i):
        mitigation = f"Remediation status: {i.remediation_status}\n"
        mitigation += f"Remediation target date: {i.remediation_target_date}\n"
        mitigation += f"Remediation actual date: {i.remediation_actual_date}\n"
        mitigation += f"Remediation comment: {i.remediation_comment}\n"

        return mitigation

    def format_reference(self, i):
        reference = f"Source: {i.vuln_source}\n"
        reference += f"URL: {i.url}\n"

        return reference
