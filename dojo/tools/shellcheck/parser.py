import json

from dojo.models import Finding


class ShellcheckParser:

    """
    Parser for ShellCheck JSON reports.

    ShellCheck is a shell script static analyser. Many of its checks are stylistic, but a
    number are security relevant -- unquoted expansions that allow word splitting and globbing,
    unsafe use of ``eval``, and unchecked ``cd`` before a destructive command -- so its results
    are imported with ShellCheck's own severity levels preserved.
    """

    # ShellCheck's own levels, from most to least serious.
    SEVERITY = {
        "error": "High",
        "warning": "Medium",
        "info": "Low",
        "style": "Info",
    }

    def get_scan_types(self):
        return ["ShellCheck Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import ShellCheck reports in JSON format, generated with 'shellcheck -f json script.sh'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for issue in data or []:
            code = issue.get("code")
            # ShellCheck reports its check id as a bare integer; the documented form is SCnnnn.
            check_id = f"SC{code}" if code is not None else None
            path = issue.get("file")
            line = issue.get("line")

            description = []
            if issue.get("message"):
                description.append(issue["message"])
            if check_id:
                description.append(f"**Check:** {check_id}")
            if path:
                description.append(f"**Location:** {path}:{line}" if line else f"**Location:** {path}")
            if issue.get("column"):
                description.append(f"**Column:** {issue['column']}")
            if issue.get("fix"):
                description.append("**Fix available:** ShellCheck can rewrite this automatically.")

            findings.append(Finding(
                title=f"{check_id}: {issue.get('message')}" if check_id else issue.get("message"),
                test=test,
                description="\n".join(description),
                severity=self.SEVERITY.get(str(issue.get("level")).lower(), "Low"),
                file_path=path,
                line=line,
                vuln_id_from_tool=check_id,
                references=f"https://www.shellcheck.net/wiki/{check_id}" if check_id else None,
                # ShellCheck emits a fix block only for the checks it can rewrite.
                fix_available=bool(issue.get("fix")),
                static_finding=True,
                dynamic_finding=False,
            ))
        return findings
