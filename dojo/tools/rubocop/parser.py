import json

from dojo.models import Finding


class RubocopParser:

    ID = "Rubocop Scan"

    # possible values are:
    # `:info`, `:refactor`, `:convention`, `:warning`, `:error` or `:fatal`.
    # see https://github.com/rubocop/rubocop/blob/master/lib/rubocop/cop/severity.rb
    # TODO change when the tool support it (not now 1.24.1, always "conventionnal")
    # current version (1.13.0) always populate severity to "conventionnal"
    # so we force it to 'Medium'
    SEVERITY_MAPPING = {
        "info": "Info",
        "refactor": "Medium",
        "convention": "Medium",  # see the note
        "warning": "Medium",
        "error": "High",
        "fatal": "Critical",
    }

    def get_scan_types(self):
        return [self.ID]

    def get_label_for_scan_types(self, scan_type):
        return self.ID

    def get_description_for_scan_types(self, scan_type):
        return "Import Rubocop JSON scan report (with option -f json)."

    def requires_file(self, scan_type):
        return True

    def get_findings(self, scan_file, test):
        """Load a file as JSON file and create findings"""
        data = json.load(scan_file)
        findings = list()
        for vuln_file in data.get("files", []):
            path = vuln_file.get("path")
            for offense in vuln_file.get("offenses", []):
                # here we are filtering out what is not security
                if not offense["cop_name"].lower().startswith("security"):
                    continue
                line = int(offense["location"]["start_line"])
                description = "\n".join(
                    [
                        f"**Message**: {offense.get('message')}",
                        f"**Is correctable?**: `{offense.get('correctable')}`",
                        f"**Location**: `{'-'.join(offense['location'])}`",
                    ]
                )
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
