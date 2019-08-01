import requests

from dojo.models import Tool_Configuration, Tool_Type
from dojo.utils import prepare_for_view


class SonarQubeAPI:

    def __init__(self):
        tool_type, _ = Tool_Type.objects.get_or_create(name='SonarQube')
        config = Tool_Configuration.objects.filter(tool_type=tool_type).get()

        self.session = requests.Session()
        self.sonar_api_url = config.url
        if config.authentication_type == "Password":
            self.session.auth = (config.username, prepare_for_view(config.password))
        elif config.authentication_type == "API":
            self.session.auth = (config.api_key, '')
        else:
            raise Exception('Authentication type not supported')

    def find_project(self, project):
        """
        Search for projects or views to administrate them.
        Requires 'System Administrator' permission
        :param project:
        :return:
        """
        response = self.session.get(
            url='{}/projects/search'.format(self.sonar_api_url),
            params={'q': project},
        )

        if response.ok:
            return response.json()['components']
        else:
            raise Exception(
                "Unable to find the product {} due to {} - {}".format(project, response.status_code, response.content)
            )

    def find_issues(self, component_key):
        """
        Search for issues.
        At most one of the following parameters can be provided at the same time:
            componentKeys, componentUuids, components, componentRootUuids, componentRoots.
        Requires the 'Browse' permission on the specified project(s).
        :param component_key:
        :return:
        """
        page = 1
        max_page = 100
        issues = list()

        while page <= max_page:
            request_filter = {
                'componentKeys': component_key,
                'types': 'BUG,VULNERABILITY,CODE_SMELL',
                'p': page
            }
            response = self.session.get(
                url='{}/issues/search'.format(self.sonar_api_url),
                params=request_filter,
            )

            if response.ok:
                issues_page = response.json().get('issues')
                if not issues_page:
                    break
                issues.extend(issues_page)
                page += 1

            else:
                raise Exception(
                    "Unable to find the issues for component {} due to {} - {}".format(
                        component_key, response.status_code, response.content
                    )
                )

        return issues

    def get_issue(self, issue_key):
        """
        Search for issues.
        At most one of the following parameters can be provided at the same time:
            componentKeys, componentUuids, components, componentRootUuids, componentRoots.
        Requires the 'Browse' permission on the specified project(s).
        :param issue_key:
        :return:
        """
        request_filter = {
            'issues': issue_key,
            'types': 'BUG,VULNERABILITY,CODE_SMELL'
        }
        response = self.session.get(
            url='{}/issues/search'.format(self.sonar_api_url),
            params=request_filter,
        )

        if response.ok:
            issue = response.json().get('issues')[0]
            if issue['key'] == issue_key:
                print(issue)
                return issue
            else:
                raise Exception("Wrong issue returned!")

        else:
            raise Exception(
                "Unable to get issue {} due to {} - {}".format(
                    issue_key, response.status_code, response.content
                )
            )

    def get_rule(self, rule_id):
        """
        Get detailed information about a rule
        :param rule_id:
        :return:
        """

        response = self.session.get(
            url='{}/rules/show'.format(self.sonar_api_url),
            params={'key': rule_id},
        )
        if response.ok:
            return response.json()['rule']
        else:
            raise Exception("Unable to get the rule {} due to {} - {}".format(
                rule_id, response.status_code, response.content
            ))

    def transition_issue(self, issue_key, transition):
        """
        Do workflow transition on an issue. Requires authentication and Browse permission on project.
        The transitions 'wontfix' and 'falsepositive' require the permission 'Administer Issues'.
        The transitions involving security hotspots (except 'requestreview') require
        the permission 'Administer Security Hotspot'.

        Possible transitions:
        - confirm
        - unconfirm
        - reopen
        - resolve
        - falsepositive
        - wontfix
        - close
        - detect
        - dismiss
        - reject
        - requestreview
        - accept
        - clear
        - reopenhotspot

        :param issue_key:
        :param transition:
        :return:
        """
        response = self.session.post(
            url='{}/issues/do_transition'.format(self.sonar_api_url),
            data={
                'issue': issue_key,
                'transition': transition
            },
        )
        if not response.ok:
            raise Exception(
                "Unable to transition {} the issue {} due to {} - {}".format(
                    transition, issue_key, response.status_code, response.content
                )
            )

    def add_comment(self, issue_key, text):
        """
        Add a comment.
        Requires authentication and the following permission: 'Browse' on the project of the specified issue.
        :param issue_key:
        :param text:
        :return:
        """
        response = self.session.post(
            url='{}/issues/add_comment'.format(self.sonar_api_url),
            data={
                'issue': issue_key,
                'text': text
            },
        )
        if not response.ok:
            raise Exception(
                "Unable to add a comment into issue {} due to {} - {}".format(
                    issue_key, response.status_code, response.content
                )
            )
