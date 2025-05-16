import hashlib

from cvss import CVSS2, CVSS3

from dojo.models import Finding

from .importer import BlackduckBinaryAnalysisImporter


class BlackduckBinaryAnalysisParser:

    """
    Report type(s) from Blackduck Binary Analysis compatible with DefectDojo:
    - Single CSV file containing vulnerable components
    """

    def get_scan_types(self):
        return ["Blackduck Binary Analysis"]

    def get_label_for_scan_types(self, scan_type):
        return "Blackduck Binary Analysis"

    def get_description_for_scan_types(self, scan_type):
        return "Blackduck Binary Analysis CSV file containing vulnerable binaries."

    def get_findings(self, filename, test):
        sorted_findings = self.sort_findings(filename)
        return self.ingest_findings(sorted_findings, test)

    def sort_findings(self, filename):
        importer = BlackduckBinaryAnalysisImporter()

        return sorted(
            importer.parse_findings(filename), key=lambda f: f.cve,
        )

    def ingest_findings(self, sorted_findings, test):
        findings = {}
        for i in sorted_findings:
            file_path = str(i.object_full_path)
            object_sha1 = i.object_sha1
            cve = i.cve
            cwe = 1357
            title = self.format_title(i)
            description = self.format_description(i)
            cvss_v3 = True
            if str(i.cvss_vector_v3) != "":
                cvss_vectors = "{}{}".format(
                    "CVSS:3.1/",
                    i.cvss_vector_v3,
                )
                cvss_obj = CVSS3(cvss_vectors)
            elif str(i.cvss_vector_v2) != "":
                # Some of the CVSSv2 vectors have a trailing
                # colon that needs to be removed
                cvss_v3 = False
                cvss_vectors = i.cvss_vector_v2.replace(":/", "/")
                cvss_obj = CVSS2(cvss_vectors)
            else:
                cvss_vectors = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
                cvss_obj = CVSS3(cvss_vectors)

            cvss_score = cvss_obj.scores()[0]
            severity = cvss_obj.severities()[0]

            mitigation = self.format_mitigation(i)
            impact = self.format_impact(i)
            references = self.format_references(i)

            unique_finding_key = hashlib.sha256(
                f"{file_path + object_sha1 + title}".encode(),
            ).hexdigest()

            if unique_finding_key in findings:
                finding = findings[unique_finding_key]
                finding.nb_occurences += 1
            else:
                finding = Finding(
                    title=title,
                    test=test,
                    cvssv3_score=cvss_score,
                    severity=severity,
                    description=description,
                    mitigation=mitigation,
                    impact=impact,
                    static_finding=True,
                    dynamic_finding=True,
                    cwe=int(cwe),
                    nb_occurences=1,
                    references=references,
                    file_path=file_path,
                    url=i.vulnerability_url,
                    vuln_id_from_tool=str(cve),
                    severity_justification=cvss_vectors,
                    component_name=i.component,
                    component_version=i.version,
                    unique_id_from_tool=unique_finding_key,
                )

                if cvss_v3:
                    finding.cvssv3 = cvss_vectors
                else:
                    finding.severity_justification = cvss_vectors

                findings[unique_finding_key] = finding

        return list(findings.values())

    def format_title(self, i):
        title = f"{i.object_name}: {i.component} {i.version} Vulnerable"

        if i.cve is not None:
            title += f" to {i.cve}"

        return title

    def format_description(self, i):
        description = f"CSV Result: {i.report_name}\n"
        description += f"Vulnerable Component: {i.component}\n"
        description += f"Vulnerable Component Version in Use: {i.version}\n"
        description += f"Vulnerable Component Latest Version: {i.latest_version}\n"
        description += f"Matching Type: {i.matching_type}\n"
        description += f"Object Name: {i.object_name}\n"
        description += f"Object Extraction Path: {i.object_full_path}\n"
        description += f"Object Compilation Date: {i.object_compilation_date}\n"
        description += f"Object SHA1: {i.object_sha1}\n"
        description += f"CVE: {i.cve}\n"
        description += f"CVE Publication Date: {i.cve_publication_date}\n"
        description += f"Distribution Package: {i.distribution_package}\n"
        description += f"Missing Exploit Mitigations: {i.missing_exploit_mitigations}\n"
        description += f"BDSA: {i.bdsa}\n"
        description += f"Summary:\n{i.summary}\n"
        description += f"Note Type:\n{i.note_type}\n"
        description += f"Note Reason:\n{i.note_reason}\n"
        description += f"Triage Vectors:\n{i.triage_vectors}\n"
        description += f"Unresolving Triage Vectors:\n{i.triage_vectors}\n"

        return description

    def format_mitigation(self, i):
        return f"Upgrade {i.component} to latest version: {i.latest_version}.\n"

    def format_impact(self, i):
        impact = "The use of vulnerable third-party open source software in applications can have numerous negative impacts:\n\n"
        impact += "1. **Security Impact**: Vulnerable software can be exploited by hackers to compromise applications or systems, leading to unauthorized access, data theft, and/or malicious activities.  This would impact the confidentiality, data integrity, and/or operational availability of software exploited.\n"
        impact += "2. **Financial Impact**: Incidents involving security breaches can result in substantial financial loss to responsible organization(s).\n"
        impact += "3. **Reputation Impact**: A security breach can greatly harm an organization's reputation. Rebuilding public trust after a breach can be a substantial and long-lasting challenge.\n"
        impact += "4. **Compliance Impact**: Many industries have strict regulations about data protection. Use of vulnerable software could compromise data security measures and result in compliance violations, leading to potential fines and other penalties.\n"

        return impact

    def format_references(self, i):
        references = f"BDSA: {i.bdsa}\n"
        references += f"NIST CVE Details: {i.vulnerability_url}\n"

        return references
