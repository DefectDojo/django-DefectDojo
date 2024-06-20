__author__ = "jankuehl"

import re

from defusedxml import ElementTree as ET

from dojo.models import Finding


class XanitizerParser:
    def get_scan_types(self):
        return ["Xanitizer Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Xanitizer Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import XML findings list report, preferably with parameter 'generateDetailsInFindingsListReport=true'."

    def get_findings(self, filename, test):
        if filename is None:
            return []

        root = self.parse_xml(filename)
        if root is not None:
            return self.get_findings_internal(root, test)
        return []

    def parse_xml(self, filename):
        try:
            tree = ET.parse(filename)
        except SyntaxError as se:
            raise ValueError(se)

        root = tree.getroot()
        if "XanitizerFindingsList" not in root.tag:
            msg = f"'{filename}' is not a valid Xanitizer findings list report XML file."
            raise ValueError(msg)

        return root

    def get_findings_internal(self, root, test):
        items = []

        globalDate = root.get("timeStamp", default=None)
        if globalDate is not None:
            # only date no time
            globalDate = globalDate[:10]

        for finding in root.findall("finding"):
            line = finding.find("line").text
            if line and int(line) <= 0:
                line = None

            date = globalDate
            if finding.find("date") is not None:
                # only date no time
                date = finding.find("date").text[:10]

            description = self.generate_description(finding)

            dojofinding = Finding(
                test=test,
                title=self.generate_title(finding, line),
                description=description,
                cwe=self.resolve_cwe(finding),
                severity=self.resolve_severity(finding),
                file_path=self.generate_file_path(finding),
                line=line,
                date=date,
                static_finding=True,
            )
            vulnerability_id = self.find_cve(description)
            if vulnerability_id:
                dojofinding.unsaved_vulnerability_ids = [vulnerability_id]

            items.append(dojofinding)

        return items

    def generate_title(self, finding, line):
        title = finding.find("problemType").text

        pckg = finding.find("package")
        cl = finding.find("class")
        file = finding.find("file")
        if pckg is not None and cl is not None:
            title = f"{title} ({pckg.text}.{cl.text}:{line})" if line else f"{title} ({pckg.text}.{cl.text})"
        else:
            title = f"{title} ({file.text}:{line})" if line else f"{title} ({file.text})"

        return title

    def generate_description(self, finding):
        description = "**Description:**\n{}".format(
            finding.find("description").text,
        )

        if finding.find("startNode") is not None:
            startnode = finding.find("startNode")
            endnode = finding.find("endNode")
            description = f"{description}\n-----\n"
            description = "{}\n**Starting at:** {} - **Line** {}".format(
                description, startnode.get("classFQN"), startnode.get("lineNo"),
            )
            description = self.add_code(startnode, showline=False, description=description)
            description = "{}\n\n**Ending at:** {} - **Line** {}".format(
                description, endnode.get("classFQN"), endnode.get("lineNo"),
            )
            description = self.add_code(endnode, showline=True, description=description)
        elif finding.find("node") is not None:
            node = finding.find("node")
            description = f"{description}\n-----\n"
            line = node.get("lineNo")
            location = node.get("classFQN")
            if location is None:
                location = node.get("relativePath")
            if line is not None and int(line) > 0:
                description = f"{description}\n**Finding at:** {location} - **Line** {line}"
            else:
                description = f"{description}\n**Finding at:** {location}"
            description = self.add_code(node, showline=True, description=description)

        return description

    def add_code(self, node, showline, description):
        codelines = node.findall("code")

        if codelines is None or len(codelines) == 0:
            return description

        if showline or len(codelines) == 1:
            for code in codelines:
                if code.get("finding") == "true":
                    description = f"{description}\n**Finding Line:** {code.text}"

        if len(codelines) > 1:
            description = f"{description}\n**Code Excerpt:** "
            for code in codelines:
                if code.text:
                    description = "{}\n{}: {}".format(
                        description, code.get("lineNo"), code.text,
                    )
                else:
                    description = "{}\n{}: ".format(
                        description, code.get("lineNo"),
                    )

        return description

    def generate_file_path(self, finding):

        if finding.find("endNode") is not None and finding.find("endNode").get(
            "relativePath",
        ):
            return finding.find("endNode").get("relativePath")
        if finding.find("node") is not None and finding.find("node").get(
            "relativePath",
        ):
            return finding.find("node").get("relativePath")

        pckg = finding.find("package")
        file = finding.find("file")
        if pckg is not None:
            return "{}/{}".format(pckg.text.replace(".", "/"), file.text)

        return file.text

    def resolve_cwe(self, finding):
        if finding.find("cweNumber") is not None:
            cwe = finding.find("cweNumber").text
            if len(cwe) > 4 and cwe[:4] == "CWE-":
                # remove leading 'CWE-' and ',' '.'
                return cwe[4:].replace(",", "").replace(".", "")

        return None

    def find_cve(self, description):
        # copy from models.py
        match = re.search(r"CVE-\d{4}-\d{4,7}", description)

        if match:
            return match.group()

        return None

    def resolve_severity(self, finding):
        if finding.find("rating") is None or not finding.find("rating").text:
            return "Info"

        rating = float(finding.find("rating").text)

        if rating == 0:
            return "Info"
        if rating < 4:
            return "Low"
        if rating < 7:
            return "Medium"
        if rating < 9:
            return "High"

        return "Critical"
