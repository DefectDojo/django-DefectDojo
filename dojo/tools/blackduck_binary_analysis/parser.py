import hashlib

from dojo.models import Finding
from .importer import BlackduckBinaryAnalysisImporter
import cvss.parser


class BlackduckBinaryAnalysisParser(object):
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

        findings = sorted(
            importer.parse_findings(filename), key=lambda f: f.cve,
        )
        return findings

    def ingest_findings(self, sorted_findings, test):
        findings = dict()
        for i in sorted_findings:
            object_sha1 = i.object_sha1
            cve = i.cve
            cwe = 1357
            title = self.format_title(i)
            description = self.format_description(i)
            if i.cvss_v3 is not None:
                cvss_v3 = True
                cvss_score = i.cvss_v3
                cvss_vectors = "{}{}".format(
                    "CVSS:3.1/",
                    i.cvss_vector_v3
                )
            elif i.cvss_v2 is not None:
                cvss_v3 = False
                cvss_score = i.cvss_v2
                cvss_vectors = i.cvss_vector_v2
            else:
                cvss_v3 = True
                cvss_score = 0.0
                cvss_vectors = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"

            cvss_obj = cvss.parser.parse_cvss_from_text(cvss_vectors)
            if not cvss_obj:
                severity = "Info"
            else:
                severity = cvss_obj[0].severities()[0]

            mitigation = self.format_mitigation(i)
            impact = self.format_impact(i)
            references = self.format_references(i)

            unique_finding_key = hashlib.sha256(
                "{}".format(object_sha1 + title).encode("utf-8")
            ).hexdigest()

            if unique_finding_key in findings:
                finding = findings[unique_finding_key]
                finding.nb_occurences += 1
            else:
                finding = Finding(
                    title=title,
                    test=test,
                    severity=severity,
                    description=description,
                    mitigation=mitigation,
                    impact=impact,
                    static_finding=True,
                    dynamic_finding=True,
                    cwe=int(cwe),
                    nb_occurences=1,
                    references=references,
                    file_path=i.object_full_path,
                    url=i.vulnerability_url,
                    vuln_id_from_tool=cve,
                    severity_justification=cvss_vectors,
                    component_name=i.component,
                    component_version=i.version,
                    unique_id_from_tool=object_sha1,
                )

                if cvss_v3:
                    finding.cvssv3 = cvss_vectors
                    finding.cvssv3_score = cvss_score

                findings[unique_finding_key] = finding

        return findings.values()

    def format_title(self, i):
        title = "{} {}: {} ({}) Vulnerable to {} per {}".format(
            i.component,
            i.version,
            i.object_name,
            i.object_sha1,
            i.cve,
            i.report_path
        )

        return title

    def format_description(self, i):
        description = "CSV Result: {}\n".format(str(i.report_path))
        description = "Component: {}\n".format(str(i.component))
        description += "Component Version in Use: {}\n".format(str(i.version))
        description += "Component Latest Version: {}\n".format(
            str(i.latest_version)
        )
        description += "Matching Type: {}\n".format(str(i.matching_type))
        description += "Vulnerable Binary: {}\n".format(
            str(i.object_name)
        )
        description += "Vulnerable Binary Extraction Path: {}\n".format(
            str(i.object_full_path)
        )
        description += "Vulnerable Binary Compilation Date: {}\n".format(
            str(i.object_compilation_date)
        )
        description += "Vulnerable Binary SHA1: {}\n".format(str(i.object_sha1))
        description += "CVE: {}\n".format(str(i.cve))
        description += "CVE Publication Date: {}\n".format(
            str(i.cve_publication_date)
        )
        description += "Distribution Package: {}\n".format(
            str(i.distribution_package)
        )
        description += "Missing Exploit Mitigations: {}\n".format(
            str(i.missing_exploit_mitigations)
        )
        description += "BDSA: {}\n".format(str(i.bdsa))
        description += "Summary:\n{}\n".format(str(i.summary))
        description += "Note Type:\n{}\n".format(str(i.note_type))
        description += "Note Reason:\n{}\n".format(str(i.note_reason))
        description += "Triage Vectors:\n{}\n".format(str(i.triage_vectors))
        description += "Unresolving Triage Vectors:\n{}\n".format(str(i.triage_vectors))

        return description

    def format_mitigation(self, i):
        mitigation = "Upgrade {} to latest version: {}.\n".format(
            str(i.component),
            str(i.latest_version)
        )

        return mitigation

    def format_impact(self, i):
        impact = "The use of vulnerable third-party open source software in applications can have numerous negative impacts:\n\n"
        impact += "1. **Security Impact**: Vulnerable software can be exploited by hackers to compromise applications or systems, leading to unauthorized access, data theft, and/or malicious activities.  This would impact the confidentiality, data integrity, and/or operational availability of software exploited.\n"
        impact += "2. **Financial Impact**: Incidents involving security breaches can result in substantial financial loss to responsible organization(s).\n"
        impact += "3. **Reputation Impact**: A security breach can greatly harm an organization’s reputation. Rebuilding public trust after a breach can be a substantial and long-lasting challenge.\n"
        impact += "4. **Compliance Impact**: Many industries have strict regulations about data protection. Use of vulnerable software could compromise data security measures and result in compliance violations, leading to potential fines and other penalties.\n"

        return impact

    def format_references(self, i):
        references = "BDSA: {}\n".format(str(i.bdsa))
        references += "NIST CVE Details: {}\n".format(str(i.vulnerability_url))

        return references
