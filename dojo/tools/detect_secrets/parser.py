import json
import hashlib
import dateutil.parser
from dojo.models import Finding


class DetectSecretsParser(object):
    """
    A class that can be used to parse the detect-secrets JSON report file
    """

    def get_scan_types(self):
        return ["Detect-secrets Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Detect-secrets Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON output for detect-secrets scan report."

    def get_findings(self, filename, test):
        data = json.load(filename)
        dupes = {}
        if data.get('generated_at'):
            find_date = dateutil.parser.parse(data.get('generated_at'))
        for detect_file in data.get('results'):
            for item in data.get('results').get(detect_file):
                type = item.get('type')
                file = item.get('filename')
                hashed_secret = item.get('hashed_secret')
                is_verified = item.get('is_verified')
                line = item.get('line_number')
                description = "Detected potential secret with the following related data:\n"
                description += "**Filename:** " + file + "\n"
                description += "**Line:** " + str(line) + "\n"
                description += "**Type:** " + type + "\n"

                dupe_key = hashlib.sha256(
                    (type + file + str(line) + hashed_secret).encode('utf-8')
                ).hexdigest()

                if dupe_key in dupes:
                    finding = dupes[dupe_key]
                    finding.nb_occurences += 1
                else:
                    finding = Finding(
                        title=f"{type}",
                        test=test,
                        description=description,
                        cwe=798,
                        date=find_date,
                        severity="High",
                        verified=is_verified,
                        file_path=file,
                        line=line,
                        nb_occurences=1,
                        false_p='is_secret' in item and item['is_secret'] is False,
                    )
                    dupes[dupe_key] = finding
        return list(dupes.values())
