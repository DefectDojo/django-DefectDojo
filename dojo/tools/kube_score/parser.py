import json

from dojo.models import Finding


class KubeScoreParser:

    """
    Parser for kube-score JSON reports.

    kube-score grades every check it runs rather than assigning a severity: 10 is a
    passing check, 5 a warning and 1 a critical. Grade 0 is used for checks that
    produced no opinion. Only the non-passing, non-skipped grades become Findings.
    """

    # kube-score's own grading scale, as emitted in the ``grade`` field.
    SEVERITY = {
        1: "High",
        5: "Medium",
    }

    def get_scan_types(self):
        return ["kube-score Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import kube-score reports in JSON format, generated with 'kube-score score --output-format json'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for obj in data or []:
            object_name = obj.get("object_name")
            file_name = obj.get("file_name")
            file_row = obj.get("file_row")
            for item in obj.get("checks", []):
                # A skipped check carries a grade but expresses no opinion on the object.
                if item.get("skipped"):
                    continue
                grade = item.get("grade")
                if grade not in self.SEVERITY:
                    continue
                check = item.get("check", {})
                findings.append(
                    self._to_finding(item, check, grade, object_name, file_name, file_row, test),
                )
        return findings

    def _to_finding(self, item, check, grade, object_name, file_name, file_row, test):
        description = [f"**Object:** {object_name}"] if object_name else []
        if check.get("comment"):
            description.append(f"**Check:** {check['comment']}")
        if check.get("target_type"):
            description.append(f"**Target type:** {check['target_type']}")
        for comment in item.get("comments", []):
            summary = comment.get("summary")
            if not summary:
                continue
            path = comment.get("path")
            description.append(f"**{path}:** {summary}" if path else f"**Finding:** {summary}")

        mitigation = "\n".join(
            comment["description"]
            for comment in item.get("comments", [])
            if comment.get("description")
        )

        finding = Finding(
            title=check.get("name"),
            test=test,
            description="\n".join(description),
            severity=self.SEVERITY[grade],
            mitigation=mitigation or None,
            component_name=object_name,
            vuln_id_from_tool=check.get("id"),
            static_finding=True,
            dynamic_finding=False,
        )
        if file_name:
            finding.file_path = file_name
            # kube-score reports row 0 for objects it could not locate in the source file.
            if file_row:
                finding.line = file_row
        return finding
