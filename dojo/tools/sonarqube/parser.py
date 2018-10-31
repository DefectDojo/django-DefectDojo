from lxml import etree
from dojo.models import Finding
from django.utils.html import strip_tags


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
        tables = list(tree.iter("tbody"))
        if len(tables) != 3:
            raise Exception('Parser ValueError')
        vulnerabilities_table = list(tables[1].iter("tr"))
        rules_table = list(tables[2].iter("tr"))

        for vuln in vulnerabilities_table:
            try:
                vuln_properties = list(vuln.iter("td"))
                vuln_rule_name = list(vuln_properties[0].iter("a"))[0].text
                vuln_severity = self.convert_sonar_severity(vuln_properties[1].text)
                vuln_title = vuln_properties[2].text
                vuln_mitigation = vuln_properties[3].text
            except:
                raise Exception('Parser ValueError')
            if vuln_title is None or vuln_mitigation is None:
                raise Exception('Parser ValueError')

            vuln_details = self.get_rule_details(vuln_rule_name, rules_table)
            if vuln_details is not None:
                vuln_description = self.get_description(vuln_details)
                vuln_references = self.get_references(vuln_details)
                vuln_cwe = self.get_cwe(vuln_references)
            else:
                vuln_description = "No description provided"
                vuln_references = ""
                vuln_cwe = 0

            find = Finding(title=vuln_title,
                           cwe=vuln_cwe,
                           description=vuln_description,
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
                           numerical_severity=Finding.get_numerical_severity(vuln_severity))
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

    def get_rule_details(self, vuln_rule_name, rules_table):
        if vuln_rule_name is not None:
            for rule in rules_table:
                try:
                    rule_properties = list(rule.iter("td"))
                    rule_name = list(rule_properties[0].iter("a"))[0].text
                    if rule_name == vuln_rule_name:
                        rule_details = list(rule_properties[1].iter("details"))[0]
                        return rule_details
                except:
                    raise Exception('Parser ValueError')
        return None

    def get_description(self, vuln_details):
        rule_description = etree.tostring(vuln_details, pretty_print=True)
        rule_description = rule_description.split("<h2>See", 1)[0]
        rule_description = (str(rule_description)).replace("<h2>", "**")
        rule_description = (str(rule_description)).replace("</h2>", "**")
        rule_description = strip_tags(rule_description).strip()
        return rule_description

    def get_references(self, vuln_details):
        rule_references = ""
        for a in vuln_details.iter("a"):
            rule_references += a.text + "\n"
        return rule_references

    def get_cwe(self, vuln_references):
        if "CWE-" in vuln_references:
            cwe = vuln_references.split("CWE-", 1)
            if ":" in cwe[1]:
                cwe = cwe[1].split(":", 1)
            elif "\n" in cwe[1]:
                cwe = cwe[1].split("\n", 1)
            return cwe[0]
        return 0
