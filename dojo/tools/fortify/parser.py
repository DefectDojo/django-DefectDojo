__guide__ = 'aaronweaver'
__author__ = 'Rajarshi333'


from defusedxml import ElementTree
from dateutil import parser
import re
from dojo.models import Finding


class FortifyXMLParser(object):
    language_list = []

    def __init__(self, filename, test):
        fortify_scan = ElementTree.parse(filename)
        root = fortify_scan.getroot()

        # Get Date
        date_string = root.getchildren()[5].getchildren()[1].getchildren()[2].text
        date_list = date_string.split()[1:4]
        date_act = "".join(date_list)
        find_date = parser.parse(date_act)

        # Get Language
        lang_string = root[8][4][2].text
        lang_need_string = re.findall("^.*com.fortify.sca.Phase0HigherOrder.Languages.*$",
                                      lang_string, re.MULTILINE)
        lang_my_string = lang_need_string[0]
        language = lang_my_string.split('=')[1]
        if language not in self.language_list:
            self.language_list.append(language)

        # Get all issues
        issues = []
        for ReportSection in root.findall('ReportSection'):
            if ReportSection.findtext('Title') == "Results Outline":
                for issue in ReportSection.iter("Issue"):
                    issues.append(issue)

        # All issues obtained, create a map for reference
        issue_map = {}
        for issue in issues:
            details = {}
            details["Category"] = issue.find("Category").text
            details["Folder"] = issue.find("Folder").text
            details["Kingdom"] = issue.find("Kingdom").text
            details["Abstract"] = issue.find("Abstract").text
            details["Friority"] = issue.find("Friority").text
            details["FileName"] = issue.find("Primary").find("FileName").text
            details["FilePath"] = issue.find("Primary").find("FilePath").text
            details["LineStart"] = issue.find("Primary").find("LineStart").text
            details["Snippet"] = issue.find("Primary").find("Snippet").text
            issue_map.update({issue.attrib['iid']: details})
        # map created

        self.items = []
        for issue_key, issue in issue_map.items():
            self.items.append(Finding(
                title=self.format_title(issue["Category"], issue["FileName"], issue["LineStart"]),
                severity=issue["Friority"],
                numerical_severity=Finding.get_numerical_severity(issue["Friority"]),
                file_path=issue['FilePath'],
                line_number=int(issue['LineStart']),
                line=int(issue['LineStart']),
                static_finding=True,
                active=False,
                verified=False,
                test=test,
                date=find_date,
                description=self.format_description(issue["Abstract"],
                                                    issue["FileName"],
                                                    issue["Snippet"]),
                unique_id_from_tool=issue_key
            ))

    def format_title(self, category, filename, line_no):
        return "{} - {}: {}".format(category, filename, line_no)

    def format_description(self, abstract, filename, snippet):
        desc = "###Abstract:\n{}\n###Snippet:\n**File: {}**\n```\n{}\n```\n".format(
                abstract, filename, snippet)
        return desc

