import logging

from lxml import etree

from dojo.tools.sonarqube.soprasteria_helper import SonarQubeSoprasteriaHelper

logger = logging.getLogger(__name__)


class SonarQubeSoprasteriaJSON:
    def get_json_items(self, json_content, test, mode):
        dupes = {}
        rules = json_content["rules"]
        issues = json_content["issues"]
        for issue in issues:
            key = issue["key"]
            line = str(issue["line"])
            mitigation = issue["message"]
            title = issue["description"]
            file_path = issue["component"]
            severity = SonarQubeSoprasteriaHelper().convert_sonar_severity(issue["severity"])
            rule_id = issue["rule"]

            if title is None or mitigation is None:
                raise ValueError(
                    "Parser ValueError: can't find a title or a mitigation for vulnerability of name "
                    + rule_id,
                )

            try:
                issue_detail = rules[rule_id]
                parser = etree.HTMLParser()
                html_desc_as_e_tree = etree.fromstring(issue_detail["htmlDesc"], parser)
                issue_description = SonarQubeSoprasteriaHelper().get_description(html_desc_as_e_tree)
                logger.debug(issue_description)
                issue_references = SonarQubeSoprasteriaHelper().get_references(
                    rule_id, html_desc_as_e_tree,
                )
                issue_cwe = SonarQubeSoprasteriaHelper().get_cwe(issue_references)
            except KeyError:
                issue_description = "No description provided"
                issue_references = ""
                issue_cwe = 0

            if mode is None:
                SonarQubeSoprasteriaHelper().process_result_file_name_aggregated(
                    test,
                    dupes,
                    title,
                    issue_cwe,
                    issue_description,
                    file_path,
                    line,
                    severity,
                    mitigation,
                    issue_references,
                )
            else:
                SonarQubeSoprasteriaHelper().process_result_detailed(
                    test,
                    dupes,
                    title,
                    issue_cwe,
                    issue_description,
                    file_path,
                    line,
                    severity,
                    mitigation,
                    issue_references,
                    key,
                )
        return list(dupes.values())
