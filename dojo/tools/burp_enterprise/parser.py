from lxml import etree
from dojo.models import Finding
from django.utils.html import strip_tags
import logging
import re

logger = logging.getLogger(__name__)


class BurpEnterpriseHtmlParser(object):

    def __init__(self, filename, test, mode=None):
        parser = etree.HTMLParser()
        tree = etree.parse(filename, parser)
        if(mode in [None, 'detailed']):
            self.mode = mode
        else:
            raise Exception("Internal error: Invalid mode " + mode + ". Expected: one of None, 'detailed'")

        # Dictonary to hold the aggregated findings with:
        #  - key: the concatenated aggregate keys
        #  - value: the finding
        self.dupes = dict()

        self.test = test
        self.impact = "No impact provided"

        if tree:
            self.items = self.get_items(tree)
        else:
            self.items = []

    def get_items(self, tree):
        # Check that there is at least one vulnerability (the vulnerabilities table is absent when no vuln are found)
        items = dict()
        severities = tree.xpath("/html/body/div/table[contains(@class, 'issue-table')]/tbody")
        sev_table = list(severities.iter("tr"))
        for item in range(0, len(sev_table), 2):
            title = list(vuln.iter("td"))[0].text.strip()[:-4]
            severity = list(vuln.iter("td"))[1].text.strip()
            vuln = dict()
            


        vulns = tree.xpath("/html/body/div/div[contains(@class, 'section details')]/div[contains(@class, 'issue-container')]")
        print('length of vulns :: ', len(vulns))
        if(len(vulns) > 1):
            itemsDict = dict()
            for vuln in vulns:
                items = vuln.iterchildren()
                title = items[1].text.strip()
                # Description



                for item in items:
                    print('tag  :: ', item.tag)
                    print('text :: ', item.text, '\n')
                    if item.text == '':
                        for p_text in item.iterchildren():
                            print('tag  :: ', item.tag)
                            print('text :: ', item.text.strip())

            raise Exception("Stop")

        # # iterate over the rules once to get the information we need
        # rulesDic = dict()
        # for rule in rules_table:
        #     rule_properties = list(rule.iter("td"))
        #     rule_name = list(rule_properties[0].iter("a"))[0].text
        #     rule_details = list(rule_properties[1].iter("details"))[0]
        #     rulesDic[rule_name] = rule_details

        # for vuln in vulnerabilities_table:
        #     vuln_properties = list(vuln.iter("td"))
        #     vuln_rule_name = list(vuln_properties[0].iter("a"))[0].text
        #     vuln_severity = self.convert_sonar_severity(vuln_properties[1].text)
        #     vuln_file_path = vuln_properties[2].text
        #     vuln_line = vuln_properties[3].text
        #     vuln_title = vuln_properties[4].text
        #     vuln_mitigation = vuln_properties[5].text
        #     vuln_key = vuln_properties[6].text
        #     if vuln_title is None or vuln_mitigation is None:
        #         raise Exception("Parser ValueError: can't find a title or a mitigation for vulnerability of name " + vuln_rule_name)
        #     try:
        #         vuln_details = rulesDic[vuln_rule_name]
        #         vuln_description = self.get_description(vuln_details)
        #         vuln_references = self.get_references(vuln_rule_name, vuln_details)
        #         vuln_cwe = self.get_cwe(vuln_references)
        #     except KeyError:
        #         vuln_description = "No description provided"
        #         vuln_references = ""
        #         vuln_cwe = 0
        #     if(self.mode is None):
        #         self.process_result_file_name_aggregated(
        #             vuln_title, vuln_cwe, vuln_description, vuln_file_path, vuln_line, vuln_severity, vuln_mitigation, vuln_references)
        #     elif (self.mode == 'detailed'):
        #         self.process_result_detailed(
        #             vuln_title, vuln_cwe, vuln_description, vuln_file_path, vuln_line, vuln_severity, vuln_mitigation, vuln_references, vuln_key)
        # items = list(self.dupes.values())

            

        else:
            # No vuln were found
            items = list()
        return items


