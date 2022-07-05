import io
import csv
import hashlib
from dojo.models import Finding


class PmdParser(object):

    def get_scan_types(self):
        return ["PMD Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "CSV Report"

    def get_findings(self, filename, test):
        dupes = dict()

        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        reader = list(csv.DictReader(io.StringIO(content), delimiter=',', quotechar='"'))

        for row in reader:
            finding = Finding(test=test)
            finding.title = f'PMD rule {row["Rule"]}'
            if row["Priority"] == "5":
                priority = "Critical"
            elif row["Priority"] == "4":
                priority = "High"
            elif row["Priority"] == "3":
                priority = "Medium"
            elif row["Priority"] == "2":
                priority = "Low"
            elif row["Priority"] == "1":
                priority = "Info"
            else:
                priority = "Info"
            finding.severity = priority

            description = "Description: {}\n".format(row['Description'].strip())
            description += "Rule set: {}\n".format(row["Rule set"].strip())
            description += "Problem: {}\n".format(row["Problem"].strip())
            description += "Package: {}\n".format(row["Package"].strip())
            finding.description = description
            finding.line = row["Line"]
            finding.file_path = row["File"]
            finding.impact = "No impact provided"
            finding.mitigation = "No mitigation provided"

            key = hashlib.sha256("|".join([
                finding.title,
                finding.description,
                finding.file_path,
                finding.line
            ]).encode("utf-8")).hexdigest()

            if key not in dupes:
                dupes[key] = finding

        return list(dupes.values())
