import csv
import io
import json
import re

from dojo.models import Finding

# ScubaGoggles renders its requirement text for the HTML report, so the JSON carries markup
# such as the "Automated Check" badges. Strip it before it reaches a Finding title.
HTML_TAG = re.compile(r"<[^>]+>")

SCAN_TYPE_RESULTS = "ScubaGoggles Scan"
SCAN_TYPE_ACTION_PLAN = "ScubaGoggles Action Plan"


def strip_html(value):
    if not value:
        return ""
    return re.sub(r"\s+", " ", HTML_TAG.sub(" ", value)).strip()


class ScubaGogglesParser:

    """
    Parser for CISA ScubaGoggles reports.

    ScubaGoggles assesses a Google Workspace tenant against the CISA SCuBA secure
    configuration baselines. Every baseline policy is graded against its criticality:
    a "Shall" is mandatory, a "Should" is recommended.
    """

    def get_scan_types(self):
        return [SCAN_TYPE_RESULTS, SCAN_TYPE_ACTION_PLAN]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        if scan_type == SCAN_TYPE_ACTION_PLAN:
            return "Import the CISA ScubaGoggles ActionPlan CSV, holding the controls that did not pass."
        return "Import CISA ScubaGoggles ScubaResults JSON, holding the full pass and fail set."

    def get_findings(self, file, test):
        content = file.read()
        content = content.decode("utf-8-sig") if isinstance(content, bytes) else content.lstrip("\ufeff")

        stripped = content.lstrip()
        if not stripped.startswith(("{", "[")):
            return self._findings_from_action_plan(content, test)

        data = json.loads(stripped)
        metadata = data.get("MetaData", {}) or {}
        tenant = metadata.get("DisplayName") or metadata.get("DomainName")

        findings = []
        for product, groups in (data.get("Results") or {}).items():
            for group in groups or []:
                for control in group.get("Controls", []):
                    severity = self._severity(control.get("Result"), control.get("Criticality"))
                    if severity is None:
                        continue
                    findings.append(
                        self._to_finding(control, group, product, tenant, severity, test),
                    )
        return findings

    def _to_finding(self, control, group, product, tenant, severity, test):
        control_id = control.get("Control ID")
        requirement = strip_html(control.get("Requirement"))
        details = strip_html(control.get("Details"))

        description = [f"**Requirement:** {requirement}"] if requirement else []
        description.extend([
            f"**Result:** {control.get('Result')}",
            f"**Criticality:** {control.get('Criticality')}",
        ])
        if group.get("GroupName"):
            description.append(f"**Baseline group:** {group['GroupName']}")
        if product:
            description.append(f"**Product:** {product}")
        if tenant:
            description.append(f"**Tenant:** {tenant}")
        if details:
            description.append(f"**Details:** {details}")

        return Finding(
            title=f"{control_id}: {requirement}" if requirement else control_id,
            test=test,
            description="\n".join(description),
            severity=severity,
            mitigation=details or None,
            references=group.get("GroupReferenceURL") or None,
            component_name=product,
            vuln_id_from_tool=control_id,
            static_finding=True,
            dynamic_finding=False,
        )

    def _severity(self, result, criticality):
        """Return the severity for a graded control, or None when it is not a finding."""
        criticality = criticality or ""
        # ScubaGoggles marks baselines it cannot evaluate as "Not-Implemented" and reports
        # them as N/A. Those are gaps in the tool, not in the tenant.
        if "Not-Implemented" in criticality:
            return None
        if result == "Fail":
            return "High" if criticality.startswith("Shall") else "Medium"
        if result == "Warning":
            return "Low"
        # Pass, N/A and "No events found" say nothing was found to be wrong.
        return None

    def _findings_from_action_plan(self, content, test):
        """The action plan is a flat CSV of the controls that did not pass."""
        reader = csv.DictReader(io.StringIO(content), delimiter=",", quotechar='"')
        findings = []
        for row in reader:
            control_id = (row.get("Control ID") or "").strip()
            if not control_id:
                continue
            severity = self._severity(row.get("Result"), row.get("Criticality"))
            if severity is None:
                continue
            findings.append(self._to_finding(row, {}, None, None, severity, test))
        return findings
