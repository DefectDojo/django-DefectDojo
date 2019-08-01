import logging
import re

from lxml import etree
import html2text

from dojo.models import Finding
from dojo.tools.sonarqube.api_client import SonarQubeAPI
from dojo.models import Sonarqube_Issue

logger = logging.getLogger(__name__)


class SonarQubeApiImporter(object):
    """
    This class imports from SonarQube (SQ) all open/confirmed SQ issues related to the project related to the test as
     findings.
    """

    def __init__(self, test):
        self.client = SonarQubeAPI()
        self.items = self.import_issues(self.client, test)

    @staticmethod
    def is_confirmed(state):
        return state.lower() in [
            'confirmed',
            'accepted',
            'detected',
        ]

    @staticmethod
    def is_closed(state):
        return state.lower() in [
            'resolved',
            'falsepositive',
            'wontfix',
            'closed',
            'dismissed',
            'rejected'
        ]

    def import_issues(self, client, test):

        items = list()
        product_name = test.engagement.product.name

        components = client.find_project(product_name)
        logging.info('Found {} components for product {}'.format(len(components), product_name))

        for component in components:

            issues = client.find_issues(component['key'])
            logging.info('Found {} issues for component {}'.format(len(issues), component["key"]))

            security_issues = [i for i in issues if ('cwe' in i['tags'])]
            logging.info('Found {} security issues for component {}'.format(len(security_issues), component["key"]))

            for security_issue in security_issues:

                status = security_issue['status']
                from_hotspot = security_issue['fromHotspot']

                if self.is_closed(status) or from_hotspot:
                    continue

                type = security_issue['type']
                title = security_issue['message']
                component_key = security_issue['component']
                line = security_issue['line']
                rule_id = security_issue['rule']
                rule = client.get_rule(rule_id)
                severity = self.convert_sonar_severity(rule['severity'])
                description = self.clean_rule_description_html(rule['htmlDesc'])
                cwe = self.clean_cwe(rule['htmlDesc'])
                references = self.get_references(rule['htmlDesc'])

                sonarqube_issue, _ = Sonarqube_Issue.objects.update_or_create(
                    key=security_issue['key'],
                    defaults={
                        'status': status,
                        'type': type,
                    }
                )

                # Only assign the SonarQube_issue to the first finding related to the issue
                if Finding.objects.filter(sonarqube_issue=sonarqube_issue).exists():
                    sonarqube_issue = None

                find = Finding(
                    title=title,
                    cwe=cwe,
                    description=description,
                    test=test,
                    severity=severity,
                    references=references,
                    file_path=component_key,
                    line=line,
                    active=True,
                    verified=self.is_confirmed(status),
                    false_p=False,
                    duplicate=False,
                    out_of_scope=False,
                    mitigated=None,
                    mitigation='No mitigation provided',
                    impact="No impact provided",
                    numerical_severity=Finding.get_numerical_severity(severity),
                    static_finding=True,
                    sonarqube_issue=sonarqube_issue,
                )
                items.append(find)

        return items

    @staticmethod
    def clean_rule_description_html(raw_html):
        search = re.search(r"^(.*?)(?:(<h2>See</h2>)|(<b>References</b>))", raw_html, re.DOTALL)
        if search:
            raw_html = search.group(1)
        h = html2text.HTML2Text()
        return h.handle(raw_html)

    @staticmethod
    def clean_cwe(raw_html):
        search = re.search(r'CWE-(\d+)', raw_html)
        if search:
            return int(search.group(1))

    @staticmethod
    def convert_sonar_severity(sonar_severity):
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

    @staticmethod
    def get_references(vuln_details):
        parser = etree.HTMLParser()
        details = etree.fromstring(vuln_details, parser)
        rule_references = ""
        for a in details.iter("a"):
            rule_references += "[{}]({})\n".format(a.text, a.get('href'))
        return rule_references
