import json

from dojo.models import Finding


class SemgrepParser:

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Semgrep Parser.

        Fields:
        - title: Set to the check_id value outputted by the Semgrep Scanner.
        - severity: Set to severity from Semgrep Scanner that has been converted to DefectDojo format.
        - description: Custom description made from elements outputted by Semgrep Scanner.
        - file_path: Set to filepath from Semgrep Scanner.
        - line: Set to line from Semgrep Scanner.
        - vuln_id_from_tool: Set to Vuln Id from Semgrep Scanner.
        - nb_occurences: Initially set to 1 then updated.
        - unique_id_from_tool: Set to corresponding field from scanner if it is present in the output.
        - cwe: Set to cwe from scanner output if present.
        - mitigation: Set to "fix" from scanner output or "fix_regex" if "fix" isn't present.
        """
        return [
            "title",
            "severity",
            "description",
            "file_path",
            "line",
            "vuln_id_from_tool",
            "nb_occurences",
            "unique_id_from_tool",
            "cwe",
            "mitigation",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Semgrep Parser.

        Fields:
        - title: Set to the title outputted by the Semgrep Scanner.
        - cwe: Set to cwe from scanner output if present.
        - line: Set to line from Semgrep Scanner.
        - file_path: Set to filepath from Semgrep Scanner.
        - description: Custom description made from elements outputted by Semgrep Scanner.

        NOTE: uses legacy dedupe: ['title', 'cwe', 'line', 'file_path', 'description']
        """
        return [
            "title",
            "cwe",
            "line",
            "file_path",
            "description",
        ]

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
                # treat "requires login" as if the fingerprint is absent
                if unique_id_from_tool == "requires login":
                    unique_id_from_tool = None

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
                if "assistant" in item["extra"] and item["extra"]["assistant"]:
                    mitigation = ""
                    severity_justification = ""
                    if item["extra"]["assistant"]["autofix"]:
                        mitigation += f"**Assistant explanation:** {item['extra']['assistant']['autofix']['explanation']} \n\n**Assistant suggested code**:\n{item['extra']['assistant']['autofix']['fix_code']}\n\n"
                    if item["extra"]["assistant"]["component"]:
                        severity_justification += f"Assistant thinks this file is {item['extra']['assistant']['component']['risk']} risk because it relates to {item['extra']['assistant']['component']['tag']}\n\n"
                    if item["extra"]["assistant"]["guidance"]:
                        mitigation += f"**Assistant guidance:**\n{item['extra']['assistant']['guidance']['summary']}\n{item['extra']['assistant']['guidance']['instructions']}\n"
                    if item["extra"]["assistant"]["autotriage"]:
                        severity_justification += f"Assistant thinks this is a {item['extra']['assistant']['autotriage']['verdict']}."
                        if item["extra"]["assistant"]["autotriage"]["reason"]:
                            severity_justification += f" {item['extra']['assistant']['autotriage']['reason']}"
                        severity_justification += "\n"
                    if mitigation != "":
                        finding.mitigation = mitigation
                    if severity_justification != "":
                        finding.severity_justification = severity_justification

                dupe_key = unique_id_from_tool

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
                # treat "requires login" as if the fingerprint is absent
                if unique_id_from_tool == "requires login":
                    unique_id_from_tool = None

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

                dupe_key = unique_id_from_tool

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
        if upper_value in {"WARNING", "MEDIUM"}:
            return "Medium"
        if upper_value in {"ERROR", "HIGH"}:
            return "High"
        if upper_value in {"LOW", "INFO"}:
            return "Low"
        msg = f"Unknown value for severity: {val}"
        raise ValueError(msg)

    def get_description(self, item):
        description = ""

        message = item["extra"]["message"]
        description += f"**Result message:** {message}\n"

        snippet = item["extra"].get("lines")
        if snippet == "requires login":
            snippet = None  # Treat "requires login" as no snippet

        if snippet is not None:
            if "<![" in snippet:
                snippet = snippet.replace("<![", "<! [")
                description += f"**Snippet:** ***Caution:*** Please remove the space between `!` and `[` to have the real value due to a workaround to circumvent [#8435](https://github.com/DefectDojo/django-DefectDojo/issues/8435).\n```{snippet}```\n"
            else:
                description += f"**Snippet:**\n```{snippet}```\n"

        return description
