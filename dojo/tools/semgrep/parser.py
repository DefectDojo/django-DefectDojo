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
                title=item["check_id"],
                severity=self.convert_severity(item["extra"]["severity"]),
                description=self.get_description(item),
                file_path=item['path'],
                line=item["start"]["line"],
                static_finding=True,
                dynamic_finding=False,
                vuln_id_from_tool=item["check_id"],
                nb_occurences=1,
            )

            # manage CWE
            if 'cwe' in item["extra"]["metadata"]:
                finding.cwe = int(item["extra"]["metadata"].get("cwe").partition(':')[0].partition('-')[2])

            # manage references from metadata
            if 'references' in item["extra"]["metadata"]:
                finding.references = "\n".join(item["extra"]["metadata"]["references"])

            # manage mitigation from metadata
            if 'fix' in item["extra"]:
                finding.mitigation = item["extra"]["fix"]
            elif 'fix_regex' in item["extra"]:
                finding.mitigation = "\n".join([
                    "**You can automaticaly apply this regex:**",
                    "\n```\n",
                    json.dumps(item["extra"]["fix_regex"]),
                    "\n```\n",
                ])

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
        elif "INFO" == val.upper():
            return "Info"
        else:
            raise ValueError(f"Unknown value for severity: {val}")

    def get_description(self, item):
        description = ''

        message = item["extra"]["message"]
        description += '**Result message:** {}\n'.format(message)

        snippet = item["extra"].get("lines")
        if snippet is not None:
            description += '**Snippet:**\n```{}```\n'.format(snippet)

        return description
