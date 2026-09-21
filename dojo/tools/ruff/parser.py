import json

from dojo.models import Finding


class RuffParser:

    """
    Parser for Ruff JSON reports.

    Ruff is a fast Python linter that includes the flake8-bandit security ruleset (its ``S``
    codes). Because a Ruff run can mix security findings with style, the parser weights by
    rule category so a real security issue is not lost among formatting noise: ``S`` codes
    are given weight, everything else stays low.
    """

    def get_scan_types(self):
        return ["Ruff Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Ruff reports in JSON format, generated with 'ruff check --output-format json'."

    def get_findings(self, file, test):
        data = json.load(file)
        return [self._to_finding(item, test) for item in data or []]

    def _to_finding(self, item, test):
        code = item.get("code")
        message = item.get("message")
        path = item.get("filename")
        location = item.get("location") or {}
        line = location.get("row")

        description = []
        if message:
            description.append(message)
        description.append(f"**Rule:** {code}")
        if item.get("url"):
            description.append(f"**Reference:** {item['url']}")
        if path:
            description.append(f"**Location:** {path}:{line}" if line else f"**Location:** {path}")
        if item.get("fix"):
            description.append("**Fix available:** Ruff can apply a fix for this rule.")

        return Finding(
            title=f"{code}: {message}" if code else message,
            test=test,
            description="\n".join(description),
            severity=self._severity(code),
            file_path=path,
            line=line,
            vuln_id_from_tool=code,
            references=item.get("url") or None,
            static_finding=True,
            dynamic_finding=False,
        )

    def _severity(self, code):
        """The S ruleset is flake8-bandit (security); the rest of Ruff is code quality."""
        if code and code.startswith("S"):
            return "Medium"
        return "Low"
