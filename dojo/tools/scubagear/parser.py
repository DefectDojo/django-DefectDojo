import csv
import io
import re

from dojo.models import Finding

# ScubaGear writes the requirement text for its HTML report, so the CSV carries the same
# markup, including the BOD 25-01 and "Automated Check" badges.
HTML_TAG = re.compile(r"<[^>]+>")


def strip_html(value):
    if not value:
        return ""
    return re.sub(r"\s+", " ", HTML_TAG.sub(" ", value)).strip()


class ScubaGearParser:

    """
    Parser for the CISA ScubaGear action plan.

    ScubaGear assesses a Microsoft 365 tenant against the CISA SCuBA secure configuration
    baselines. The ActionPlan CSV holds the controls that did not pass, each graded against
    its criticality: a "Shall" is mandatory, a "Should" is recommended.
    """

    def get_scan_types(self):
        return ["ScubaGear Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import the CISA ScubaGear ActionPlan CSV, assessing Microsoft 365 against the SCuBA baselines."

    def get_findings(self, filename, test):
        # ScubaGear writes the action plan with a UTF-8 byte order mark.
        content = filename.read()
        content = content.decode("utf-8-sig") if isinstance(content, bytes) else content.lstrip("﻿")
        reader = csv.DictReader(io.StringIO(content), delimiter=",", quotechar='"')

        findings = []
        for row in reader:
            control_id = (row.get("Control ID") or "").strip()
            if not control_id:
                continue
            severity = self._severity(row.get("Result"), row.get("Criticality"))
            if severity is None:
                continue
            findings.append(self._to_finding(row, control_id, severity, test))
        return findings

    def _to_finding(self, row, control_id, severity, test):
        requirement = strip_html(row.get("Requirement"))
        details = strip_html(row.get("Details"))

        description = [f"**Requirement:** {requirement}"] if requirement else []
        description.extend([
            f"**Result:** {(row.get('Result') or '').strip()}",
            f"**Criticality:** {(row.get('Criticality') or '').strip()}",
        ])
        if details:
            description.append(f"**Details:** {details}")
        reason = strip_html(row.get("Non-Compliance Reason"))
        if reason:
            description.append(f"**Non-compliance reason:** {reason}")
        justification = strip_html(row.get("Justification"))
        if justification:
            description.append(f"**Justification:** {justification}")

        return Finding(
            title=f"{control_id}: {requirement}" if requirement else control_id,
            test=test,
            description="\n".join(description),
            severity=severity,
            mitigation=details or None,
            vuln_id_from_tool=control_id,
            static_finding=True,
            dynamic_finding=False,
        )

    def _severity(self, result, criticality):
        """Return the severity for a control, or None when the row is not a finding."""
        result = (result or "").strip()
        criticality = (criticality or "").strip()
        # Baselines ScubaGear does not evaluate are reported as Not-Implemented. They
        # describe a gap in the tool rather than in the tenant.
        if "Not-Implemented" in criticality:
            return None
        if result == "Fail":
            return "High" if criticality.startswith("Shall") else "Medium"
        if result == "Warning":
            return "Low"
        return None
