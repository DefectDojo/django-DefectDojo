from defusedxml import ElementTree

from dojo.models import Endpoint, Finding


class FortifyXMLParser:
    def parse_xml(self, filename, test):
        fortify_scan = ElementTree.parse(filename)
        root = fortify_scan.getroot()
        if root.tag == "Scan":
            return self.xml_structure_24_2(root, test)
        if root.tag == "ReportDefinition":
            return self.xml_structure_before_24_2(root, test)
        raise ValueError

    def xml_structure_24_2(self, root, test):
        items = []
        for issues in root.findall("Issues"):
            for issue in issues.iter("Issue"):
                check_type_id = issue.find("CheckTypeID").text
                engine_type = issue.find("EngineType").text
                url = issue.find("URL").text
                scheme = issue.find("Scheme").text
                host = issue.find("Host").text
                port = issue.find("Port").text
                vulnerable_session = issue.find("VulnerableSession").text
                vulnerability_id = issue.find("VulnerabilityID").text
                severity = issue.find("Severity").text
                name = issue.find("Name").text
                raw_response = issue.find("RawResponse").text
                description = ""
                description += "**CheckTypeID:** " + check_type_id + "\n"
                description += "**URL:** " + url + "\n"
                description += "**EngineType:** " + engine_type + "\n"
                description += "**Scheme:** " + scheme + "\n"
                description += "**VulnerabilityID:** " + vulnerability_id + "\n"
                description += "**VulnerableSession:** " + vulnerable_session + "\n"
                finding = Finding(
                        title=name,
                        severity=self.severity_translator(severity=int(severity)),
                        static_finding=True,
                        test=test,
                        description=description,
                    )
                if raw_response is not None:
                    finding.unsaved_req_resp = []
                    finding.unsaved_req_resp.append({"req": "", "resp": str(raw_response)})
                if host is not None:
                    finding.unsaved_endpoints = [Endpoint(host=host, port=port)]
                items.append(finding)
        return items

    def severity_translator(self, severity):
        if severity == 0:
            return "Info"
        if severity == 1:
            return "Low"
        if severity == 2:
            return "Medium"
        if severity == 3:
            return "High"
        if severity == 4:
            return "Critical"
        return "Info"

    def xml_structure_before_24_2(self, root, test):
        # Get Category Information:
        # Abstract, Explanation, Recommendation, Tips
        cat_meta = {}
        # Get all issues
        issues = []
        meta_pair = ({}, {})
        issue_pair = ([], [])
        for ReportSection in root.findall("ReportSection"):
            if ReportSection.findtext("Title") in {
                "Results Outline",
                "Issue Count by Category",
            }:
                place = (
                    0
                    if ReportSection.findtext("Title") == "Results Outline"
                    else 1
                )
                # Get information on the vulnerability like the Abstract, Explanation,
                # Recommendation, and Tips
                for group in ReportSection.iter("GroupingSection"):
                    title = group.findtext("groupTitle")
                    maj_attr_summary = group.find("MajorAttributeSummary")
                    if maj_attr_summary:
                        meta_info = maj_attr_summary.findall("MetaInfo")
                        meta_pair[place][title] = {
                            x.findtext("Name"): x.findtext("Value")
                            for x in meta_info
                        }
                # Collect all issues
                for issue in ReportSection.iter("Issue"):
                    issue_pair[place].append(issue)
        if len(issue_pair[0]) > len(issue_pair[1]):
            issues = issue_pair[0]
            cat_meta = meta_pair[0]
        else:
            issues = issue_pair[1]
            cat_meta = meta_pair[1]
        # All issues obtained, create a map for reference
        issue_map = {}
        for issue in issues:
            issue.attrib["iid"]
            details = {
                "Category": issue.find("Category").text,
                "Folder": issue.find("Folder").text,
                "Kingdom": issue.find("Kingdom").text,
                "Abstract": issue.find("Abstract").text,
                "Friority": issue.find("Friority").text,
                "FileName": issue.find("Primary").find("FileName").text,
                "FilePath": issue.find("Primary").find("FilePath").text,
                "LineStart": issue.find("Primary").find("LineStart").text,
            }
            if issue.find("Primary").find("Snippet"):
                details["Snippet"] = issue.find("Primary").find("Snippet").text
            else:
                details["Snippet"] = "n/a"
            if issue.find("Source"):
                source = {
                    "FileName": issue.find("Source").find("FileName").text,
                    "FilePath": issue.find("Source").find("FilePath").text,
                    "LineStart": issue.find("Source").find("LineStart").text,
                    "Snippet": issue.find("Source").find("Snippet").text,
                }
                details["Source"] = source
            issue_map.update({issue.attrib["iid"]: details})
        items = []
        dupes = set()
        for issue_key, issue in issue_map.items():
            title = self.format_title(
                issue["Category"], issue["FileName"], issue["LineStart"],
            )
            if title not in dupes:
                items.append(
                    Finding(
                        title=title,
                        severity=issue["Friority"],
                        file_path=issue["FilePath"],
                        line=int(issue["LineStart"]),
                        static_finding=True,
                        test=test,
                        description=self.format_description(issue, cat_meta),
                        mitigation=self.format_mitigation(issue, cat_meta),
                        unique_id_from_tool=issue_key,
                    ),
                )
                dupes.add(title)
        return items

    def format_description(self, issue, meta_info) -> str:
        """
        Returns a formatted Description. This will contain information about the category,
        snippet from the code, including the file and line number. If there is source information
        it will also include that. Adds explanation of finding from the meta info
        :param issue:       Issue Dictionary
        :param meta_info:   Meta Dictionary
        :return: str
        """
        desc = "##Catagory: {}\n".format(issue["Category"])
        desc += "###Abstract:\n{}\n###Snippet:\n**File: {}: {}**\n```\n{}\n```\n".format(
            issue["Abstract"],
            issue["FileName"],
            issue["LineStart"],
            issue["Snippet"],
        )
        explanation = meta_info[issue["Category"]].get("Explanation")
        source = issue.get("Source")
        if source:
            desc += (
                "##Source:\nThis snippet provides more context on the execution path that "
                "leads to this finding. \n"
                "####Snippet:\n**File: {}: {}**\n```\n{}\n```\n".format(
                    source["FileName"], source["LineStart"], source["Snippet"],
                )
            )
        if explanation:
            desc += f"##Explanation:\n {explanation}"
        return desc

    def format_title(self, category, filename, line_no):
        """
        Builds the title much like it is represented in Fortify
        :param category: Basically the title of the issue in the code
        :param filename: File where it is found
        :param line_no:  Line number of offending line
        :return: str
        """
        return f"{category} - {filename}: {line_no}"

    def format_mitigation(self, issue, meta_info) -> str:
        """
        Built from the meta_info of a category. All items of the same category will
        have the same information in it
        :param issue:  Issue dictionary
        :param meta_info:  Meta_info dictionary
        :return: str
        """
        mitigation = ""
        recommendation = meta_info[issue["Category"]].get("Recommendations")
        if recommendation:
            mitigation += f"###Recommendation:\n {recommendation}\n"
        tips = meta_info[issue["Category"]].get("Tips")
        if tips:
            mitigation += f"###Tips:\n {tips}"
        return mitigation
