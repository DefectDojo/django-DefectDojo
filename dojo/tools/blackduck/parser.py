import hashlib
from dojo.models import Finding
import dojo.tools.blackduck.importer as import_helper


class BlackduckHubCSVParser(object):
    """
    security.csv fields, base 1
    1 project id -- ignore
    2 version id -- ignore
    3 chan version id -- ignore
    4 Project name
    5 Version NO -- part of channel id
    6 channel version origin (i.e maven)
    7 Channel version origin id YES
    8 channel version origin name NO, part of ID already
    9 Vulnerability id (either a CVE or some random number from VULNDB?)
    10 Description
    11 Published on
    12 Updated on
    13 Base score
    14 Exploitability
    15 Impact
    16 Vulnerability source
    17 Remediation status (NEW, DUPLICATE...)
    18 Remediation target date
    19 Remediation actual date
    20 Remediation comment
    21 URL (can be empty)
    22 Security Risk
    """
    def __init__(self, filename, test):
        normalized_findings = self.normalize_findings(filename)
        self.ingest_findings(normalized_findings, test)

    def normalize_findings(self, filename):
        importer = import_helper.BlackduckImporter()

        findings = sorted(importer.parse_findings(filename), key=lambda f: f.vuln_id)
        return findings

    def ingest_findings(self, normalized_findings, test):
        dupes = dict()
        self.items = normalized_findings

        for i in normalized_findings:
            cve = i.vuln_id
            cwe = 0  # need a way to automaticall retrieve that see #1119
            title = self.format_title(i)
            description = self.format_description(i)
            severity = str(i.security_risk.title())
            mitigation = self.format_mitigation(i)
            impact = i.impact
            references = self.format_reference(i)

            dupe_key = hashlib.md5("{} | {}".format(title, i.vuln_source)
                .encode("utf-8")) \
                .hexdigest()

            if dupe_key in dupes:
                finding = dupes[dupe_key]
                if finding.description:
                    finding.description += "Vulnerability ID: {}\n {}\n".format(
                        cve, i.vuln_source)
                dupes[dupe_key] = finding
            else:
                dupes[dupe_key] = True

                finding = Finding(title=title,
                                  cwe=int(cwe),
                                  cve=cve,
                                  test=test,
                                  active=False,
                                  verified=False,
                                  description=description,
                                  severity=severity,
                                  numerical_severity=Finding.get_numerical_severity(
                                      severity),
                                  mitigation=mitigation,
                                  impact=impact,
                                  references=references,
                                  url=i.url,
                                  file_path=i.locations,
                                  static_finding=True
                                  )

                dupes[dupe_key] = finding

        self.items = dupes.values()

    def format_title(self, i):
        return "{} - {}".format(i.vuln_id, i.channel_version_origin_id)

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
        mitigation += "Remdediation actual date: {}\n".format(i.remediation_actual_date)
        mitigation += "Remdediation comment: {}\n".format(i.remediation_comment)

        return mitigation

    def format_reference(self, i):
        reference = "Source: {}\n".format(i.vuln_source)
        reference += "URL: {}\n".format(i.url)

        return reference
