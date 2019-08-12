from lxml import etree
from dojo.models import Finding
from django.utils.html import strip_tags
import logging
import re

logger = logging.getLogger(__name__)


class SonarQubeHtmlParser(object):

    def __init__(self, filename, test):
        parser = etree.HTMLParser()
        tree = etree.parse(filename, parser)

        if tree:
            self.items = self.get_items(tree, test)
        else:
            self.items = []

    def get_items(self, tree, test):
        items = list()
        # Check that there is at least one vulnerability (the vulnerabilities table is absent when no vuln are found)
        detailTbody = tree.xpath("/html/body/div[contains(@class,'detail')]/table/tbody")
        if(len(detailTbody) == 2):
            # First is "Detail of the Detected Vulnerabilities" (not present if no vuln)
            # Second is "Known Security Rules"
            vulnerabilities_table = list(detailTbody[0].iter("tr"))
            rules_table = list(detailTbody[1].xpath("tr"))

            # iterate over the rules once to get the information we need
            rulesDic = dict()
            for rule in rules_table:
                rule_properties = list(rule.iter("td"))
                rule_name = list(rule_properties[0].iter("a"))[0].text
                rule_details = list(rule_properties[1].iter("details"))[0]
                rulesDic[rule_name] = rule_details

            for vuln in vulnerabilities_table:
                vuln_properties = list(vuln.iter("td"))
                vuln_rule_name = list(vuln_properties[0].iter("a"))[0].text
                vuln_severity = self.convert_sonar_severity(vuln_properties[1].text)
                vuln_file_path = vuln_properties[2].text
                vuln_line = vuln_properties[3].text
                vuln_title = vuln_properties[4].text
                vuln_mitigation = vuln_properties[5].text
                if vuln_title is None or vuln_mitigation is None:
                    raise Exception("Parser ValueError: can't find a title or a mitigation for vulnerability of name " + vuln_rule_name)
                try:
                    vuln_details = rulesDic[vuln_rule_name]
                    vuln_description = self.get_description(vuln_details)
                    vuln_references = self.get_references(vuln_rule_name, vuln_details)
                    vuln_cwe = self.get_cwe(vuln_references)
                except KeyError:
                    vuln_description = "No description provided"
                    vuln_references = ""
                    vuln_cwe = 0
                find = Finding(title=vuln_title,
                               cwe=int(vuln_cwe),
                               description=vuln_description,
                               file_path=vuln_file_path,
                               line=vuln_line,
                               test=test,
                               severity=vuln_severity,
                               mitigation=vuln_mitigation,
                               references=vuln_references,
                               active=False,
                               verified=False,
                               false_p=False,
                               duplicate=False,
                               out_of_scope=False,
                               mitigated=None,
                               impact="No impact provided",
                               numerical_severity=Finding.get_numerical_severity(vuln_severity),
                               static_finding=True,
                               dynamic_finding=False)
                items.append(find)
        return items

    def convert_sonar_severity(self, sonar_severity):
        sev = sonar_severity.lower()
        if sev == "blocker":
            return "Critical"
        elif sev == "critical":
            return "High"
        elif sev == "major":
            return "Medium"
        elif sev == "minor":
            return "Low"
        else:
            return "Info"

    def get_description(self, vuln_details):
        rule_description = etree.tostring(vuln_details, pretty_print=True).decode('utf-8', errors='replace')
        rule_description = rule_description.split("<h2>See", 1)[0]
        rule_description = (str(rule_description)).replace("<h2>", "**")
        rule_description = (str(rule_description)).replace("</h2>", "**")
        rule_description = strip_tags(rule_description).strip()
        return rule_description

    def get_references(self, rule_name, vuln_details):
        rule_references = rule_name
        for a in vuln_details.iter("a"):
            rule_references += "\n" + a.text
        return rule_references

    def get_cwe(self, vuln_references):
        # Match only the first CWE!
        cweSearch = re.search("CWE-([0-9]*)", vuln_references, re.IGNORECASE)
        if cweSearch:
            return cweSearch.group(1)
        else:
            return 0
