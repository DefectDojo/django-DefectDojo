import json
import hashlib
from dojo.models import Finding
from dateutil import parser


class GgshieldParser(object):
    """
    A class that can be used to parse the Gitleaks JSON report files
    """

    def get_scan_types(self):
        return ["Ggshield Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Ggshield Scan findings in JSON format."

    def get_findings(self, filename, test):
        """
        Converts a Ggshield report to DefectDojo findings
        """
        json_data = json.load(filename)
        issues = json_data.get('scans')
        dupes = dict()

        for issue in issues:
            if issue.get('total_incidents') > 0:
                findings = {}
                commit = issue.get('id')
                extra_info = issue.get('extra_info')
                findings["commit"] = commit
                findings["author"] = extra_info.get('author')
                findings["email"] = extra_info.get('email')
                date = parser.parse(extra_info.get('date'))
                commit_date = str(date).split(" ")[0]
                findings["commit_date"] = commit_date
                for entity in issue.get('entities_with_incidents'):
                    file_path = entity.get('filename')
                    findings["file_path"] = file_path
                    for incident in entity.get('incidents'):
                        policy = incident.get('policy')
                        secret_key_type = incident.get('type')
                        total_occurrences = incident.get('total_occurrences')
                        findings["policy"] = policy
                        findings["secret_key_type"] = secret_key_type
                        findings["total_occurrences"] = total_occurrences
                        for item in incident.get('occurrences'):
                            self.get_items(item, findings, dupes, test)
        return list(dupes.values())

    def get_items(self, item, findings, dupes, test):
        findings["match"] = item.get('match')
        findings["type"] = item.get('type')
        line_start = item.get('line_start')
        line_end = item.get('line_end')
        if line_start:
            line_start = int(line_start)
        if line_end:
            line_end = int(line_end)
        findings["line_start"] = item.get('line_start')
        findings["line_end"] = item.get('line_end')
        title = f'Hard coded {findings["secret_key_type"]} found in {findings["file_path"]}'
        severity = "High"

        if "*" in findings["match"]:
            findings["match"] = findings["match"].replace("*", "-")
        description = ''
        if findings["match"]:
            description += f'**Secret:** {findings["match"]}\n'
        if findings["type"]:
            description += f'**Type:** {findings["type"]}\n'
        if findings["file_path"]:
            description += f'**File path:** {findings["file_path"]}\n'
        if findings["commit"]:
            description += f'**Commit hash:** {findings["commit"]}\n'
        if findings["line_start"]:
            description += f'**Start line:** {findings["line_start"]}\n'
        if findings["line_end"]:
            description += f'**End line:** {findings["line_end"]}\n'
        if findings["commit_date"]:
            description += f'**Commit date:** {findings["commit_date"]}\n'
        if findings["secret_key_type"]:
            description += f'**Key type:** {findings["secret_key_type"]}\n'
        if findings["author"]:
            description += f'**Author:** {findings["author"]}\n'
        if findings["email"]:
            description += f'**Email:** {findings["email"]}\n'

        finding = Finding(
            title=title,
            test=test,
            description=description,
            cwe=798,
            severity=severity,
            file_path=findings["file_path"],
            line=findings["line_start"],
            dynamic_finding=False,
            static_finding=True,
            date=findings["commit_date"]
        )

        key = hashlib.md5((title + findings["match"] + str(findings["line_start"]) + str(findings["line_end"])).encode("utf-8")).hexdigest()

        if key not in dupes:
            dupes[key] = finding
