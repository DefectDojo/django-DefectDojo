import json

from dojo.models import Finding


class GosecParser:
    def get_scan_types(self):
        return ["Gosec Scanner"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Gosec Scanner findings in JSON format."

    def get_findings(self, filename, test):
        tree = filename.read()
        try:
            data = json.loads(str(tree, "utf-8"))
        except Exception:
            data = json.loads(tree)
        dupes = {}

        for item in data["Issues"]:
            impact = ""
            references = ""
            findingdetail = ""
            title = ""
            cwe_id = None
            filename = item.get("file")
            line = item.get("line")
            scanner_confidence = item.get("confidence")

            title = item["details"] + " - rule " + item["rule_id"]

            #           Finding details information
            findingdetail += f"Filename: {filename}\n\n"
            findingdetail += f"Line number: {line}\n\n"
            findingdetail += f"Issue Confidence: {scanner_confidence}\n\n"
            findingdetail += "Code:\n\n"
            findingdetail += "```{}```".format(item["code"])

            sev = item["severity"]

            # Extract CWE information if available
            cwe_data = item.get("cwe", {})
            if cwe_data:
                cwe_id_str = cwe_data.get("id")
                if cwe_id_str:
                    cwe_id = int(cwe_id_str)
                cwe_url = cwe_data.get("url")
                if cwe_url:
                    references = cwe_url

            # If no CWE URL, fall back to gosec rule documentation
            if not references:
                references = "https://securego.io/docs/rules/{}.html".format(
                    item["rule_id"],
                ).lower()

            if scanner_confidence:
                # Assign integer value to confidence.
                if scanner_confidence == "HIGH":
                    scanner_confidence = 1
                elif scanner_confidence == "MEDIUM":
                    scanner_confidence = 4
                elif scanner_confidence == "LOW":
                    scanner_confidence = 7

            if "-" in line:
                # if this is a range, only point to the beginning.
                line = line.split("-", 1)[0]
            line = int(line) if line.isdigit() else None

            dupe_key = title + item["file"] + str(line)

            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                dupes[dupe_key] = True

                find = Finding(
                    title=title,
                    test=test,
                    description=findingdetail,
                    severity=sev.title(),
                    impact=impact,
                    references=references,
                    file_path=filename,
                    line=line,
                    cwe=cwe_id,
                    scanner_confidence=scanner_confidence,
                    static_finding=True,
                )

                dupes[dupe_key] = find

        return list(dupes.values())
