import csv
import io
from datetime import datetime
from django.conf import settings
from django.utils import timezone
from dojo.models import Finding


class VeracodeCSVParser(object):
    vc_severity_mapping = {
        1: "Info",
        2: "Low",
        3: "Medium",
        4: "High",
        5: "Critical",
    }

    def get_findings(self, file, test):
        if file is None:
            return ()
        return self.get_findings_csv(file, test)

    def get_findings_csv(self, file, test):
        content = file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        reader = csv.DictReader(
            io.StringIO(content), delimiter=",", quotechar='"'
        )
        csvarray = []

        for row in reader:
            csvarray.append(row)

        findings = []
        for row in csvarray:
            if row.get("Issue type") != "Vulnerability":
                continue

            issueId = row.get("Issue ID", None)
            if not issueId:
                # Workaround for possible encoding issue
                issueId = list(row.values())[0]
            library = row.get("Library", None)
            if row.get("Package manager") == "MAVEN" and row.get(
                "Coordinate 2"
            ):
                library = row.get("Coordinate 2")
            version = row.get("Version in use", None)
            vuln_id = row.get("CVE", None)
            if vuln_id and not (
                vuln_id.startswith("cve") or vuln_id.startswith("CVE")
            ):
                vuln_id = "CVE-" + vuln_id

            severity = self.fix_severity(row.get("Severity", None))
            cvss_score = float(row.get("CVSS score", 0))
            # Get the date based on the first_seen setting
            try:
                if settings.USE_FIRST_SEEN:
                    date = datetime.strptime(
                        row.get("Issue opened: Scan date"), "%d %b %Y %H:%M%p %Z"
                    )
                else:
                    date = datetime.strptime(
                        row.get("Issue opened: Scan date"), "%d %b %Y %H:%M%p %Z"
                    )
            except Exception:
                date = None

            description = (
                "Project name: {0}\n"
                "Title: \n>{1}"
                "\n\n-----\n\n".format(row.get("Project"), row.get("Title"))
            )

            finding = Finding(
                test=test,
                title=f"{library}:{version} | {vuln_id}",
                description=description,
                severity=severity,
                component_name=library,
                component_version=version,
                static_finding=True,
                dynamic_finding=False,
                unique_id_from_tool=issueId,
                date=date,
                nb_occurences=1,
            )

            finding.unsaved_vulnerability_ids = [vuln_id]
            if cvss_score:
                finding.cvssv3_score = cvss_score

            if (
                row.get("Ignored")
                and row.get("Ignored").capitalize() == "True"
                or row.get("Status")
                and row.get("Status").capitalize() == "Resolved"
            ):
                finding.is_mitigated = True
                finding.mitigated = timezone.now()
                finding.active = False

            findings.append(finding)

        return findings

    def fix_severity(self, severity):
        severity = severity.capitalize()
        if severity is None:
            severity = "Medium"
        elif "Unknown" == severity or "None" == severity:
            severity = "Info"
        return severity
