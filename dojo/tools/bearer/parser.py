import json
from dojo.models import Finding


class BearerParser(object):
    """
    Bearer CLI tool is a SAST scanner for multiple languages

    Base Structure:
    {
        "critical": [
            {
                "cwe_ids": [
                    "328"
                ],
                "id": "php_lang_weak_hash_md",
                "title": "Usage of weak hashing library (MDx)",
                "description": "## Description\n\nA weak hashing library can lead to data breaches and greater security risk.\n\n## Remediations\n\nAccording to [OWASP](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption), MD5 is considered a weak hashing algorithms and therefore shouldn't be used.\n\n❌ Avoid libraries and algorithms with known weaknesses:\n\n```php\n  $encrypted = md5($input)\n```\n\n✅ Use stronger encryption algorithms when storing data.\n\n```php\n  $encrypted = hash('sha256', $input)\n```\n",
                "documentation_url": "https://docs.bearer.com/reference/rules/php_lang_weak_hash_md",
                "line_number": 31,
                "full_filename": "demo.php",
                "filename": "demo.php",
                "category_groups": [
                    "PII",
                    "Personal Data",
                    "Personal Data (Sensitive)"
                ],
                "source": {
                    "start": 31,
                    "end": 31,
                    "column": {
                    "start": 20,
                    "end": 78
                    }
                },
                "sink": {
                    "start": 31,
                    "end": 31,
                    "column": {
                    "start": 20,
                    "end": 78
                    },
                    "content": "content"
                },
                "parent_line_number": 31,
                "snippet": "content",
                "fingerprint": "d150ed2257371d33a3ff618d13e5b9a8_0",
                "old_fingerprint": "ac8bb3963b25ad44bebea06c9978fc58_5",
                "code_extract": "content"
            }
        ],
        "high": [
        ],
        "medium": [
        ],
        "low": [
        ]
    }
    """

    def get_scan_types(self):
        return ["Bearer CLI"]

    def get_label_for_scan_types(self, scan_type):
        return "Bearer CLI"

    def get_description_for_scan_types(self, scan_type):
        return "Bearer CLI report file can be imported in JSON format (option -f json)."

    def get_findings(self, file, test):
        data = json.load(file)

        items = list()
        dupes = set()

        for content in data:
            severity = content.capitalize()
            for bearerfinding in data[content]:
                print(bearerfinding)

                if bearerfinding["fingerprint"] in dupes:
                    continue
                else:
                    dupes.add(bearerfinding["fingerprint"])

                finding = Finding(
                    title=bearerfinding["title"] + " in " + bearerfinding["filename"] + ":" + str(bearerfinding["line_number"]),
                    test=test,
                    description=bearerfinding["description"] + "\n Detected code snippet: \n" + bearerfinding["snippet"],
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

                items.append(finding)

        return items
