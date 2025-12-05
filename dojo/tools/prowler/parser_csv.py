import csv
import hashlib
import io
from dojo.models import Finding

class ProwlerParserCSV(object):
    """Parser for Prowler CSV (semicolon-separated)."""

    def get_findings(self, filename, test):
        if filename is None:
            return []

        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode('utf-8')
        reader = csv.DictReader(io.StringIO(content), delimiter=';')
        csvarray = []
        for row in reader:
            csvarray.append(row)

        dupes = dict()
        for row in csvarray:

            # Skip vulnerability if the status is "PASS", continue parsing is status is "FAIL" or "MANUAL"
            if row.get('STATUS') == 'PASS':
                continue

            provider = row.get('PROVIDER', 'N/A')
            # Set provider name to the correct capitalization format
            if provider == "kubernetes" or provider == "azure":
                provider = provider.capitalize()
            else:
                provider =provider.upper()

            description = (
                "**Cloud Type** : " + provider + "\n\n" +
                "**Description** : " + row.get('DESCRIPTION', 'N/A') + "\n\n" +
                "**Service Name** : " + row.get('SERVICE_NAME', 'N/A') + "\n\n" +
                "**Status Detail** : " + row.get('STATUS_EXTENDED', 'N/A') + "\n\n" +
                "**Finding Created Time** : " + row.get('TIMESTAMP', 'N/A') + "\n\n" +
                "**Region** : " + row.get('REGION', 'N/A') + "\n\n" +
                "**Notes** : " + row.get('NOTES', 'N/A')
            )

            related = row.get('RELATED_URL', '')
            additional = row.get('ADDITIONAL_URLS', '')
            if related:
                description += "\n\n**Related URL** : " + related
            if additional:
                description += "\n\n**Additional URLs** : " + additional

            mitigation = (
                "**Remediation Recommendation** : " + row.get('REMEDIATION_RECOMMENDATION_TEXT', 'N/A') + "\n\n" +
                "**Remediation Recommendation URL** : " + row.get('REMEDIATION_RECOMMENDATION_URL', 'N/A') + "\n\n" +
                "**Remediation Code Native IaC** : " + row.get('REMEDIATION_CODE_NATIVEIAC', 'N/A') + "\n\n" +
                "**Remediation Code Terraform** : " + row.get('REMEDIATION_CODE_TERRAFORM', 'N/A') + "\n\n" +
                "**Remediation Code CLI** : " + row.get('REMEDIATION_CODE_CLI', 'N/A') + "\n\n" +
                "**Other Remediation Info** : " + row.get('REMEDIATION_CODE_OTHER', 'N/A')
            )

            title = row.get('CHECK_TITLE', '')
            severity = self.convert_severity(row.get('SEVERITY'))
            impact = row.get('RISK', '')
            compliance = row.get('COMPLIANCE', 'N/A')

            # If compliance is not 'N/A', break info into multiple lines
            if compliance != "N/A":
                references = "\n".join(part.strip() for part in compliance.split("|"))
            else:
                references = "N/A"

            finding = Finding(
                title=title,
                test=test,
                description=description,
                severity=severity,
                references=references,
                mitigation=mitigation,
                impact=impact,
                static_finding=False,
                dynamic_finding=True,
            )

            key = hashlib.sha256((finding.title + '|' + finding.description).encode("utf-8")).hexdigest()
            if key not in dupes:
                dupes[key] = finding

        return list(dupes.values())

    def convert_severity(self, severity: str) -> str:
        """Convert severity value"""
        if not severity:
            return "Info"
            
        s = severity.lower()
        if s == "critical":
            return "Critical"
        elif s == "high":
            return "High"
        elif s == "medium":
            return "Medium"
        elif s == "low":
            return "Low"
        else:
            return "Info"
