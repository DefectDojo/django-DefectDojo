import pandas as pd
import hashlib
from dojo.models import Finding


class BlackduckHubCSVParser(object):
    """
    security.csv fields
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
        dupes = dict()
        self.items = ()

        if filename is None:
            self.items = ()
            return

        df = pd.read_csv(filename, header=0)
        df = df.fillna("N/A")

        for i, row in df.iterrows():
            cve = df.ix[i, 'Vulnerability id']
            cwe = 0  # need a way to automaticall retrieve that see #1119
            title = self.format_title(df, i)
            description = self.format_description(df, i)
            severity = str(df.ix[i, 'Security Risk']).title()
            mitigation = self.format_mitigation(df, i)
            impact = df.ix[i, 'Impact']
            references = self.format_reference(df, i)

            dupe_key = hashlib.md5((title + '|' + df.ix[i, 'Vulnerability source']).encode("utf-8")).hexdigest()

            if dupe_key in dupes:
                finding = dupes[dupe_key]
                if finding.description:
                    finding.description += "Vulnerability ID: {}\n {}\n".format(
                        df.ix[i, 'Vulnerability id'], df.ix[i, 'Vulnerability source'])
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
                                  url=df.ix[i, 'URL'],
                                  dynamic_finding=True)

                dupes[dupe_key] = finding

        self.items = list(dupes.values())

    def format_title(self, df, i):
        return "{} - {}".format(df.ix[i, 'Vulnerability id'], df.ix[i, 'Channel version origin id'])

    def format_description(self, df, i):
        description = "Published on: {}\n\n".format(str(df.ix[i, 'Published on']))
        description += "Updated on: {}\n\n".format(str(df.ix[i, 'Updated on']))
        description += "Base score: {}\n\n".format(str(df.ix[i, 'Base score']))
        description += "Exploitability: {}\n\n".format(str(df.ix[i, 'Exploitability']))
        description += "Description: {}\n".format(df.ix[i, 'Description'])

        return description

    def format_mitigation(self, df, i):
        mitigation = "Remediation status: {}\n".format(df.ix[i, 'Remediation status'])
        mitigation += "Remediation target date: {}\n".format(df.ix[i, 'Remediation target date'])
        mitigation += "Remdediation actual date: {}\n".format(df.ix[i, 'Remediation actual date'])
        mitigation += "Remdediation comment: {}\n".format(df.ix[i, 'Remediation comment'])

        return mitigation

    def format_reference(self, df, i):
        reference = "Source: {}\n".format(df.ix[i, 'Vulnerability source'])
        reference += "URL: {}\n".format(df.ix[i, 'URL'])

        return reference
