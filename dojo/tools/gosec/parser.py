import json

from dojo.models import Finding


class GosecParser(object):

    def get_scan_types(self):
        return ["Gosec Scanner"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Gosec Scanner findings in JSON format."

    def get_findings(self, filename, test):
        tree = filename.read()
        try:
            data = json.loads(str(tree, 'utf-8'))
        except:
            data = json.loads(tree)
        dupes = dict()

        for item in data["Issues"]:
            impact = ''
            references = ''
            findingdetail = ''
            title = ''
            filename = item.get("file")
            line = item.get("line")
            scanner_confidence = item.get("confidence")

            title = item["details"] + " - rule " + item["rule_id"]

#           Finding details information
            findingdetail += "Filename: {}\n\n".format(filename)
            findingdetail += "Line number: {}\n\n".format(str(line))
            findingdetail += "Issue Confidence: {}\n\n".format(scanner_confidence)
            findingdetail += "Code:\n\n"
            findingdetail += "```{}```".format(item["code"])

            sev = item["severity"]
            # Best attempt at ongoing documentation provided by gosec, based on rule id
            references = "https://securego.io/docs/rules/{}.html".format(item['rule_id']).lower()

            if scanner_confidence:
                # Assign integer value to confidence.
                if scanner_confidence == "HIGH":
                    scanner_confidence = 1
                elif scanner_confidence == "MEDIUM":
                    scanner_confidence = 4
                elif scanner_confidence == "LOW":
                    scanner_confidence = 7

            if '-' in line:
                # if this is a range, only point to the beginning.
                line = line.split('-', 1)[0]
            if line.isdigit():
                line = int(line)
            else:
                line = None

            dupe_key = title + item["file"] + str(line)

            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                dupes[dupe_key] = True

                find = Finding(title=title,
                               test=test,
                               description=findingdetail,
                               severity=sev.title(),
                               impact=impact,
                               references=references,
                               file_path=filename,
                               line=line,
                               scanner_confidence=scanner_confidence,
                               static_finding=True)

                dupes[dupe_key] = find

        return list(dupes.values())
