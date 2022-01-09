import json

from dojo.models import Finding


class RubocopParser:

    ID = "Rubocop Scan"

    SEVERITY_MAPPING = {"convention": "Info"}

    def get_scan_types(self):
        return [self.ID]

    def get_label_for_scan_types(self, scan_type):
        return self.ID

    def get_description_for_scan_types(self, scan_type):
        return "Import Rubocop JSON scan report (with option -f json)."

    def requires_file(self, scan_type):
        return True

    def get_findings(self, scan_file, test):
        data = json.load(scan_file)
        findings = list()
        for vuln_file in data.get("files", []):
            path = vuln_file.get("path")
            for offense in vuln_file.get("offenses", []):
                # here we are filtering out what is not security
                if not offense["cop_name"].lower().startswith("security"):
                    continue
                line = int(offense["location"]["start_line"])
                description = "\n".join([
                    f"**Message**: {offense.get('message')}",
                    f"**Is correctable?**: `{offense.get('correctable')}`",
                    f"**Location**: `{'-'.join(offense['location'])}`",
                ])
                finding = Finding(
                    test=test,
                    title=offense.get("message"),
                    severity=self.SEVERITY_MAPPING[offense["severity"]],
                    description=description,
                    file_path=path,
                    line=line,
                    vuln_id_from_tool=offense["cop_name"],
                    static_finding=True,
                    dynamic_finding=False,
                )
                findings.append(finding)
        return findings
