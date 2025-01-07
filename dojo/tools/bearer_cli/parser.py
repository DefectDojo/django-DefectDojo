import json

from dojo.models import Finding
from django.conf import settings

class BearerCLIParser:

    """Bearer CLI tool is a SAST scanner for multiple languages"""

    def get_scan_types(self):
        return ["Bearer CLI"]

    def get_label_for_scan_types(self, scan_type):
        return "Bearer CLI"

    def get_description_for_scan_types(self, scan_type):
        return "Bearer CLI report file can be imported in JSON format (option -f json)."

    def get_findings(self, file, test):
        data = json.load(file)

        items = []
        dupes = set()

        for content in data:
            severity = content.capitalize()
            for bearerfinding in data[content]:

                if bearerfinding["fingerprint"] in dupes:
                    continue
                dupes.add(bearerfinding["fingerprint"])

                finding = Finding(
                    title=bearerfinding["title"] + " in " + bearerfinding["filename"] + ":" + str(bearerfinding["line_number"]),
                    test=test,
                    description=bearerfinding["description"] + "\n Detected code snippet: \n" + bearerfinding.get("snippet", bearerfinding.get("code_extract")),
                    severity=severity,
                    cwe=bearerfinding["cwe_ids"][0],
                    static_finding=True,
                    dynamic_finding=False,
                    references=bearerfinding["documentation_url"],
                    file_path=bearerfinding["filename"],
                    line=bearerfinding["line_number"],
                    sast_sink_object=bearerfinding["sink"],
                    sast_source_object=bearerfinding["source"],
                    sast_source_line=bearerfinding["source"]["start"],
                    sast_source_file_path=bearerfinding["filename"],
                    vuln_id_from_tool=bearerfinding["id"],
                )
                finding.unsaved_tags = [settings.DD_CUSTOM_TAG_PARSER.get("bearer_cli")]
                items.append(finding)

        return items
