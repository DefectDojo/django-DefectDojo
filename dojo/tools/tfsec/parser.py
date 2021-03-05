import io
import csv
import hashlib
from dojo.models import Finding


class TfsecParser(object):

    def get_scan_types(self):
        return ["Tfsec Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "CSV Report"

    def get_findings(self, filename, test):
        dupes = dict()

        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        reader = csv.DictReader(io.StringIO(content), delimiter=',', quotechar='"')
        csvarray = []

        for row in reader:
            csvarray.append(row)

        for row in csvarray:
            finding = Finding(test=test)
            if row["severity"] == "5":
                priority = "Critical"
            elif row["severity"] == "4":
                priority = "High"
            elif row["severity"] == "3":
                priority = "Medium"
            elif row["severity"] == "WARNING":
                priority = "Low"
            elif row["severity"] == "1":
                priority = "Info"
            else:
                priority = row["severity"]
            finding.severity = priority

            description = "Description: {}\n".format(row['description'].strip())
            description += "Rule: {}\n".format(row["rule_id"].strip())
            finding.description = description
            finding.line = row["start_line"]
            # finding.line = row["start_line"] + "~" + row["end_line"]
            finding.file_path = row["file"]

            if "for more information" in row["link"]:
                try:
                    finding.url = row["link"].rsplit("for more information", 1)[0].strip().split(" ")[1].strip()
                except:
                    finding.url = row["link"].rsplit("for more information", 1)[0].strip()

            if finding is not None:
                if finding.title is None:
                    finding.title = ""
                if finding.description is None:
                    finding.description = ""

                key = hashlib.md5((finding.title + '|' + finding.line + "|" + row["rule_id"]).encode("utf-8")).hexdigest()

                if key not in dupes:
                    dupes[key] = finding

        return list(dupes.values())
