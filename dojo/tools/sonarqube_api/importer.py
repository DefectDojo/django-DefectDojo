import logging
import re
import textwrap

import html2text
from dateutil import parser
from django.conf import settings
from dojo.models import Finding
from dojo.tools.sonarqube_api import SonarQubeAPI
from lxml import etree
from sonarqube import SonarCloudClient, SonarQubeClient

logger = logging.getLogger(__name__)


class SonarQubeApiImporter(object):
    """
    This class imports from SonarQube (SQ) all open/confirmed SQ issues related to the project related to the test as
     findings.
    """

    def get_findings(self, filename, test):
        rules = dict()
        items = self.import_issues(test, rules)
        if settings.SONARQUBE_API_PARSER_HOTSPOTS:
            items.extend(self.import_hotspots(test, rules))
        return items

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

    @staticmethod
    def is_reviewed(state):
        return state.lower() in [
            'reviewed'
        ]

    @staticmethod
    def prepare_client(test):
        product = test.engagement.product
        if test.api_scan_configuration:
            config = test.api_scan_configuration  # https://github.com/DefectDojo/django-DefectDojo/pull/4676 case no. 7 and 8
            # Double check of config
            if config.product != product:
                raise Exception('Product API Scan Configuration and Product do not match.')
        else:
            sqqs = product.product_api_scan_configuration_set.filter(product=product)
            if sqqs.count() == 1:  # https://github.com/DefectDojo/django-DefectDojo/pull/4676 case no. 4
                config = sqqs.first()
            elif sqqs.count() > 1:  # https://github.com/DefectDojo/django-DefectDojo/pull/4676 case no. 6
                raise Exception(
                    'More than one Product API Scan Configuration has been configured, but none of them has been chosen.\n'
                    'Please specify at Test which one should be used.'
                )
            else:  # https://github.com/DefectDojo/django-DefectDojo/pull/4676 cases no. 1-3
                config = None

        return SonarQubeAPI(tool_config=config.sonarqube_tool_config if config else None), config

    def import_issues(self, test, rules):

        items = list()

        client, config = self.prepare_client(test)

        if config and config.service_key_1:  # https://github.com/DefectDojo/django-DefectDojo/pull/4676 cases no. 5 and 8
            component = client.get_project(config.service_key_1)
        else:  # https://github.com/DefectDojo/django-DefectDojo/pull/4676 cases no. 2, 4 and 7
            component = client.find_project(test.engagement.product.name)

        # issues = client.issues.search_issues(componentKeys=component["key"], branch="master", languages="py", types="BUG,VULNERABILITY")
        issues = client.issues.search_issues(componentKeys=component["key"], types="VULNERABILITY")
        for issue in issues:
            status = issue['status']
            from_hotspot = issue.get('fromHotspot', False)

            if self.is_closed(status) or from_hotspot:
                continue

            rule_id = issue['rule']
            if rule_id not in rules:
                if config.service_key_2:
                    rules[rule_id] = client.rules.get_rule(key=rule_id, organization=config.service_key_2)['rule']
                else:
                    rules[rule_id] = client.rules.get_rule(key=rule_id)['rule']
            rule = rules[rule_id]
            # custom (user defined) SQ rules may not have 'htmlDesc'
            if 'htmlDesc' in rule:
                description = self.clean_rule_description_html(rule['htmlDesc'])
                cwe = self.clean_cwe(rule['htmlDesc'])
                references = self.get_references(rule['htmlDesc'])
                import json
                references = json.dumps(rule, indent=2)
            else:
                description = ""
                cwe = 0
                references = ""

            find = Finding(
                title=textwrap.shorten(issue['message'], 511),
                date=parser.parse(issue["creationDate"]),
                cwe=cwe,
                description=description,
                test=test,
                severity=self.convert_sonar_severity(issue['severity']),
                references=references,
                file_path=issue['component'].split(":")[-1],
                line=issue.get('line'),
                verified=self.is_confirmed(status),
                false_p=False,
                duplicate=False,
                out_of_scope=False,
                mitigated=None,
                static_finding=True,
                dynamic_finding=False,
                unique_id_from_tool=f"issue:{issue['key']}",
            )
            items.append(find)

        return items

    def import_hotspots(self, test, rules):

        items = list()
        client, config = self.prepare_client(test)

        # if config and config.service_key_1:  # https://github.com/DefectDojo/django-DefectDojo/pull/4676 cases no. 5 and 8
        #     component = client.get_project(config.service_key_1)
        # else:  # https://github.com/DefectDojo/django-DefectDojo/pull/4676 cases no. 2, 4 and 7
        #     component = client.find_project(test.engagement.product.name)
        component = config

        # get the hotspots
        # hotspots = client.hotspots.search_hotspots(componentKeys=component["key"], branch="master")
        hotspots = client.hotspots.search_hotspots(projectKey=component["key"], branch="master")

        for hotspot in hotspots:
            status = hotspot['status']

            if self.is_reviewed(status):
                continue

            print(hotspot)
            if 'rule' in hotspot:
                rule_id = hotspot['rule']
                if rule_id not in rules:
                    rules[rule_id] = client.rules.get_rule(key=rule_id, organization='damiencarol')['rule']
                rule = rules[rule_id]

                cwe = self.clean_cwe(rule['fixRecommendations'])
                description = self.clean_rule_description_html(rule['vulnerabilityDescription'])
                references = self.get_references(rule['riskDescription']) + self.get_references(rule['fixRecommendations'])
            else:
                cwe = 0
                description = ""
                references = ""

            find = Finding(
                title=textwrap.shorten(text=hotspot['message'], width=511),
                date=parser.parse(hotspot["creationDate"]),
                cwe=cwe,
                description=description,
                references=references,
                severity='Info',
                file_path=hotspot['component'].split(":")[-1],
                line=hotspot.get('line'),
                active=True,
                verified=self.is_confirmed(status),
                false_p=False,
                duplicate=False,
                out_of_scope=False,
                static_finding=True,
                dynamic_finding=False,
                scanner_confidence=self.convert_scanner_confidence(hotspot['vulnerabilityProbability']),
                unique_id_from_tool=f"hotspot:{hotspot['key']}",
            )
            items.append(find)

        return items

    @staticmethod
    def clean_rule_description_html(raw_html):
        search = re.search(r"^(.*?)(?:(<h2>See</h2>)|(<b>References</b>))", raw_html, re.DOTALL)
        if search:
            raw_html = search.group(1)
        h = html2text.HTML2Text()
        raw_html = raw_html.replace('<h2>', '<b>').replace('</h2>', '</b>')
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
    def convert_scanner_confidence(sonar_scanner_confidence):
        sev = sonar_scanner_confidence.lower()
        if sev == "high":
            return 1
        elif sev == "medium":
            return 4
        elif sev == "low":
            return 7
        else:
            return 7

    @staticmethod
    def get_references(vuln_details):
        parser = etree.HTMLParser()
        details = etree.fromstring(vuln_details, parser)
        rule_references = ""
        for a in details.iter("a"):
            rule_references += "[{}]({})\n".format(a.text, a.get('href'))
        return rule_references
