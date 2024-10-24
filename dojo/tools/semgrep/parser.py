import json

from dojo.models import Finding


class SemgrepParser:
    def get_scan_types(self):
        return ["Semgrep JSON Report"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import Semgrep output (--json)"

    def get_findings(self, filename, test):
        data = json.load(filename)

        dupes = {}

        if "results" in data:
            for item in data.get("results", []):
                finding = Finding(
                    test=test,
                    title=item.get("check_id"),
                    severity=self.convert_severity(item["extra"]["severity"]),
                    description=self.get_description(item),
                    file_path=item["path"],
                    line=item["start"]["line"],
                    static_finding=True,
                    dynamic_finding=False,
                    vuln_id_from_tool=item["check_id"],
                    nb_occurences=1,
                )

                # fingerprint detection
                unique_id_from_tool = item.get("extra", {}).get("fingerprint")
                if unique_id_from_tool:
                    finding.unique_id_from_tool = unique_id_from_tool

                # manage CWE
                if "cwe" in item["extra"]["metadata"]:
                    if isinstance(item["extra"]["metadata"].get("cwe"), list):
                        finding.cwe = int(
                            item["extra"]["metadata"]
                            .get("cwe")[0]
                            .partition(":")[0]
                            .partition("-")[2],
                        )
                    else:
                        finding.cwe = int(
                            item["extra"]["metadata"]
                            .get("cwe")
                            .partition(":")[0]
                            .partition("-")[2],
                        )

                # manage references from metadata
                if "references" in item["extra"]["metadata"]:
                    finding.references = "\n".join(
                        item["extra"]["metadata"]["references"],
                    )

                # manage mitigation from metadata
                if "fix" in item["extra"]:
                    finding.mitigation = item["extra"]["fix"]
                elif "fix_regex" in item["extra"]:
                    finding.mitigation = "\n".join(
                        [
                            "**You can automaticaly apply this regex:**",
                            "\n```\n",
                            json.dumps(item["extra"]["fix_regex"]),
                            "\n```\n",
                        ],
                    )

                dupe_key = finding.title + finding.file_path + str(finding.line)

                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    find.nb_occurences += 1
                else:
                    dupes[dupe_key] = finding

        elif "vulns" in data:
            for item in data.get("vulns", []):
                finding = Finding(
                    test=test,
                    title=item.get("title"),
                    severity=self.convert_severity(item["advisory"]["severity"]),
                    description=item.get("advisory", {}).get("description"),
                    file_path=item["dependencyFileLocation"]["path"],
                    line=item["dependencyFileLocation"]["startLine"],
                    static_finding=True,
                    dynamic_finding=False,
                    vuln_id_from_tool=item["repositoryId"],
                    nb_occurences=1,
                )

                # fingerprint detection
                unique_id_from_tool = item.get("extra", {}).get("fingerprint")
                if unique_id_from_tool:
                    finding.unique_id_from_tool = unique_id_from_tool

                # manage CWE
                if "cweIds" in item["advisory"]["references"]:
                    if isinstance(item["advisory"]["references"].get("cweIds"), list):
                        finding.cwe = int(
                            item["advisory"]["references"]
                            .get("cweIds")[0]
                            .partition(":")[0]
                            .partition("-")[2],
                        )
                    else:
                        finding.cwe = int(
                            item["advisory"]["references"]
                            .get("cweIds")
                            .partition(":")[0]
                            .partition("-")[2],
                        )

                dupe_key = finding.title + finding.file_path + str(finding.line)

                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    find.nb_occurences += 1
                else:
                    dupes[dupe_key] = finding

        return list(dupes.values())

    def convert_severity(self, val):
        upper_value = val.upper()
        if upper_value == "CRITICAL":
            return "Critical"
        if upper_value in ["WARNING", "MEDIUM"]:
            return "Medium"
        if upper_value in ["ERROR", "HIGH"]:
            return "High"
        if upper_value == "LOW":
            return "Low"
        if upper_value == "INFO":
            return "Info"
        msg = f"Unknown value for severity: {val}"
        raise ValueError(msg)

    def get_description(self, item):
        description = ""

        message = item["extra"]["message"]
        description += f"**Result message:** {message}\n"

        snippet = item["extra"].get("lines")
        if snippet is not None:
            if "<![" in snippet:
                snippet = snippet.replace("<![", "<! [")
                description += f"**Snippet:** ***Caution:*** Please remove the space between `!` and `[` to have the real value due to a workaround to circumvent [#8435](https://github.com/DefectDojo/django-DefectDojo/issues/8435).\n```{snippet}```\n"
            else:
                description += f"**Snippet:**\n```{snippet}```\n"

        return description
