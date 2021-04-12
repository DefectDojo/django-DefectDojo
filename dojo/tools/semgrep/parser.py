import json

from dojo.models import Finding


class SemgrepParser(object):

    def get_scan_types(self):
        return ["Semgrep JSON Report"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import Semgrep output (--json)"

    def get_findings(self, filename, test):
        data = json.load(filename)

        dupes = dict()

        for item in data["results"]:
            finding = Finding(
                test=test,
                title=item["extra"]["message"].split(".")[0],
                severity=self.convert_severity(item["extra"]["severity"]),
                numerical_severity=Finding.get_numerical_severity(self.convert_severity(item["extra"]["severity"])),
                description=item["extra"]["message"],
                file_path=item['path'],
                cwe=int(item["extra"]["metadata"].get("cwe").partition(':')[0].partition('-')[2]),
                line=item["start"]["line"],
                references="\n".join(item["extra"]["metadata"]["references"]),
                mitigation=item["extra"]["fix"],
                static_finding=True,
                dynamic_finding=False,
                vuln_id_from_tool=item["check_id"],
                nb_occurences=1,
            )

            dupe_key = finding.title + finding.file_path + str(finding.line)

            if dupe_key in dupes:
                find = dupes[dupe_key]
                find.nb_occurences += 1
            else:
                dupes[dupe_key] = finding

        return list(dupes.values())

    def convert_severity(self, val):
        if "WARNING" == val.upper():
            return "Low"
        elif "ERROR" == val.upper():
            return "High"
        else:
            raise ValueError(f"Unknown value for severity: {val}")
