import requests
from requests.exceptions import JSONDecodeError as RequestsJSONDecodeError

from dojo.models import Tool_Configuration, Tool_Type
from dojo.utils import prepare_for_view


class SonarQubeAPI:

    def __init__(self, tool_config=None):

        self.rules_cache = {}

        tool_type, _ = Tool_Type.objects.get_or_create(name='SonarQube')

        if not tool_config:  # https://github.com/DefectDojo/django-DefectDojo/pull/4676 cases no. 1-3
            try:
                tool_config = Tool_Configuration.objects.get(tool_type=tool_type)  # https://github.com/DefectDojo/django-DefectDojo/pull/4676 case no. 2
            except Tool_Configuration.DoesNotExist:  # https://github.com/DefectDojo/django-DefectDojo/pull/4676 case no. 1
                raise Exception(
                    'No SonarQube tool is configured. \n'
                    'Create a new Tool at Settings -> Tool Configuration'
                )
            except Tool_Configuration.MultipleObjectsReturned:  # https://github.com/DefectDojo/django-DefectDojo/pull/4676 case no. 3
                raise Exception(
                    'More than one Tool Configuration for SonarQube exists. \n'
                    'Please specify at Product configuration which one should be used.'
                )

        supported_issue_types = ["BUG", "VULNERABILITY", "CODE_SMELL"]
        self.org_id = None
        self.extras = None
        # Parse the extras field to extract issue types and org id
        # This case is when org id and  types are both supplied seperated by a vertical bar
        if tool_config.extras and '|' in tool_config.extras:
            split_extras = tool_config.extras.split('|')
            # Iterate through the options as it is unknow which entry came first
            for entry in split_extras:
                if 'OrgID' in entry:
                    self.org_id = entry.replace('OrgID=', '')
                else:
                    self.extras = entry
        # The types must not be supplied, so assume it is only org id
        elif tool_config.extras and 'OrgID' in tool_config.extras:
            self.org_id = tool_config.extras.replace('OrgID=', '')
        # Does not appear the org id is present, set the whole field as the types
        else:
            self.extras = tool_config.extras

        # Validate the extras field to ensure only supported types are imported
        if self.extras:
            split_issue_types = self.extras.split(',')
            all_clean = all(entry in supported_issue_types for entry in split_issue_types)
            if not all_clean:
                raise Exception(f"Deteced unsupported issue type! Supported types are {', '.join(supported_issue_types)}")

        self.session = requests.Session()
        self.default_headers = {
            'User-Agent': 'DefectDojo'
        }
        self.sonar_api_url = tool_config.url
        if tool_config.authentication_type == "Password":
            self.session.auth = (tool_config.username, prepare_for_view(tool_config.password))
        elif tool_config.authentication_type == "API":
            self.session.auth = (tool_config.api_key, '')
        else:
            raise Exception(f'SonarQube Authentication type {tool_config.authentication_type} not supported')

    def find_project(self, project_name, organization=None, branch=None):
        """
        Search for projects by name.
        :param project_name:
        :return:
        """
        parameters = {
            'q': project_name,
            'qualifiers': 'TRK'
        }

        if branch:
            parameters['branch'] = branch

        if organization:
            parameters['organization'] = organization
        elif self.org_id:
            parameters['organization'] = self.org_id

        response = self.session.get(
            url=f'{self.sonar_api_url}/components/search',
            params=parameters,
            headers=self.default_headers,
        )

        if not response.ok:
            raise Exception(f'Unable to find the project {project_name} due to {response.status_code} - {response.content.decode("utf-8")}')

        for component in response.json().get('components', []):
            if component['name'] == project_name:
                return component
        raise Exception(f"""
                'Expected Project "{project_name}", but it returned {[x.get('name') for x in response.json().get('components')]}. \n'
                'Project Name is case sensitive and must match the DefectDojo Product Name. \n'
                'Alternatively it can also be specified the Project Key at Product configuration.
                """)

    def get_project(self, project_key, organization=None, branch=None):
        """
        Returns a component (project).
        Requires the following permission: 'Browse' on the project of the specified component.
        :param project_key:
        :return:
        """
        parameters = {
            'component': project_key,
        }

        if branch:
            parameters['branch'] = branch

        if organization:
            parameters['organization'] = organization
        elif self.org_id:
            parameters['organization'] = self.org_id

        response = self.session.get(
            url=f'{self.sonar_api_url}/components/show',
            params=parameters,
            headers=self.default_headers)

        if not response.ok:
            raise Exception(f'Unable to find the project {project_key} due to {response.status_code} - {response.content.decode("utf-8")}')

        return response.json().get('component')

    def find_issues(self, component_key, types='VULNERABILITY', organization=None, branch=None):
        """
        Search for issues.
        At most one of the following parameters can be provided at the same time:
            componentKeys, componentUuids, components, componentRootUuids, componentRoots.
        Requires the 'Browse' permission on the specified project(s).
        :param component_key: component key
        :param types: issue types (comma separated values). e.g. BUG,VULNERABILITY,CODE_SMELL
        :return:
        """

        if self.extras is not None:
            types = self.extras

        page = 1
        max_page = 100
        issues = []

        while page <= max_page:
            request_filter = {
                'componentKeys': component_key,
                'types': types,
                'p': page
            }

            if branch:
                request_filter['branch'] = branch

            if organization:
                request_filter['organization'] = organization
            elif self.org_id:
                request_filter['organization'] = self.org_id

            response = self.session.get(
                url=f'{self.sonar_api_url}/issues/search',
                params=request_filter,
                headers=self.default_headers,
            )

            if not response.ok:
                raise Exception(f'Unable to find the issues for component {component_key} due to {response.status_code} - {response.content.decode("utf-8")}')

            issues_page = response.json().get('issues')
            if not issues_page:
                break
            issues.extend(issues_page)
            page += 1

        return issues

    def find_hotspots(self, project_key, organization=None, branch=None):
        """
        Search for hotspots.
        :param project_key: project key
        :return:
        """
        page = 1
        max_page = 100
        hotspots = []

        while page <= max_page:
            request_filter = {
                'projectKey': project_key,
                'p': page
            }

            if branch:
                request_filter['branch'] = branch

            if organization:
                request_filter['organization'] = organization
            elif self.org_id:
                request_filter['organization'] = self.org_id

            response = self.session.get(
                url=f'{self.sonar_api_url}/hotspots/search',
                params=request_filter,
                headers=self.default_headers,
            )

            if not response.ok:
                raise Exception(f"Unable to find the hotspots for project {project_key} due to {response.status_code} - {response.content}")

            hotspots_page = response.json().get('hotspots')
            if not hotspots_page:
                break
            hotspots.extend(hotspots_page)
            page += 1

        return hotspots

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
            url=f'{self.sonar_api_url}/issues/search',
            params=request_filter,
            headers=self.default_headers,
        )

        if not response.ok:
            raise Exception(f'Unable to get issue {issue_key} due to {response.status_code} - {response.content.decode("utf-8")}')

        issues = response.json().get('issues', [])
        for issue in issues:
            if issue['key'] == issue_key:
                return issue
        raise Exception(f"""Expected Issue "{issue_key}", but it returned {[x.get('key') for x in response.json().get('issues')]}.""")

    def get_rule(self, rule_id):
        """
        Get detailed information about a rule
        :param rule_id:
        :return:
        """
        rule = self.rules_cache.get(rule_id)
        if not rule:
            response = self.session.get(
                url=f'{self.sonar_api_url}/rules/show',
                params={'key': rule_id},
                headers=self.default_headers,
            )
            if not response.ok:
                raise Exception(f'Unable to get the rule {rule_id} due to {response.status_code} - {response.content.decode("utf-8")}')

            rule = response.json()['rule']
            self.rules_cache.update({rule_id: rule})
        return rule

    def get_hotspot_rule(self, rule_id):
        """
        Get detailed information about a hotspot
        :param rule_id:
        :return:
        """
        rule = self.rules_cache.get(rule_id)
        if not rule:
            response = self.session.get(
                url=f'{self.sonar_api_url}/hotspots/show',
                params={'hotspot': rule_id},
                headers=self.default_headers,
            )
            if not response.ok:
                raise Exception(f"Unable to get the hotspot rule {rule_id} due to {response.status_code} - {response.content}")

            rule = response.json()['rule']
            self.rules_cache.update({rule_id: rule})
        return rule

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
            url=f'{self.sonar_api_url}/issues/do_transition',
            data={
                'issue': issue_key,
                'transition': transition
            },
            headers=self.default_headers,
        )

        if not response.ok:
            raise Exception(f'Unable to transition {transition} the issue {issue_key} due to {response.status_code} - {response.content.decode("utf-8")}')

    def add_comment(self, issue_key, text):
        """
        Add a comment.
        Requires authentication and the following permission: 'Browse' on the project of the specified issue.
        :param issue_key:
        :param text:
        :return:
        """
        response = self.session.post(
            url=f'{self.sonar_api_url}/issues/add_comment',
            data={
                'issue': issue_key,
                'text': text
            },
            headers=self.default_headers,
        )
        if not response.ok:
            raise Exception(f'Unable to add a comment into issue {issue_key} due to {response.status_code} - {response.content.decode("utf-8")}')

    def test_connection(self):
        """
        Returns number of components (projects) or raise error.
        """
        parameters = {
            'qualifiers': 'TRK'
        }

        if self.org_id is not None:
            parameters['organization'] = self.org_id

        response = self.session.get(
            url=f'{self.sonar_api_url}/components/search',
            params=parameters,
            headers=self.default_headers,
        )

        if not response.ok:
            raise Exception(f'Unable to connect and search in SonarQube due to {response.status_code} - {response.content.decode("utf-8")}')

        try:
            num_projects = response.json()['paging']['total']
        except RequestsJSONDecodeError:
            raise Exception(f"""
                Test request was successful (there was no HTTP-4xx or HTTP-5xx) but response doesn't contain expected JSON response.
                SonarQube responded with HTTP-{response.status_code} ({response.reason}).
                This is full response: {response.text}
                """)
        return f'You have access to {num_projects} projects'

    def test_product_connection(self, api_scan_configuration):
        organization = api_scan_configuration.service_key_2 or None
        project = self.get_project(api_scan_configuration.service_key_1, organization=organization)
        project_name = project.get('name')
        message_prefix = 'You have access to project'
        return f'{message_prefix} {project_name} in the {organization} organization' if organization else f'{message_prefix} {project_name}'
