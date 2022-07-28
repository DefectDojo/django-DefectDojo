import requests
from urllib.parse import quote

from dojo.models import Tool_Type


class BugcrowdAPI:
    """
    A simple client for the bugcrowd.io API
    """

    bugcrowd_api_url = "https://api.bugcrowd.com"

    def __init__(self, tool_config):
        tool_type, _ = Tool_Type.objects.get_or_create(name='Bugcrowd API')

        self.session = requests.Session()
        if tool_config.authentication_type == "API":
            self.api_token = tool_config.api_key
        else:
            raise Exception('bugcrowd Authentication type {} not supported'.format(tool_config.authentication_type))

    def get_findings(self, program, target):
        """
        Returns the findings for a given bugcrowd program and target, if target is *, everything is returned
        :param program:
        :param target:
        :return:
        """
        if target:
            response = self.session.get(
                url='{}/submissions?filter%5Bprogram%5D={}&filter%5Btarget%5D={}&page%5Blimit%5D=100&page%5Boffset%5D=0&include=monetary_rewards,target&filter%5Bduplicate%5D=false&sort=submitted-desc'.format(self.bugcrowd_api_url, program, quote(target)),
                headers=self.get_headers(),
            )
        else:
            response = self.session.get(
                url='{}/submissions?filter%5Bprogram%5D={}&page%5Blimit%5D=100&page%5Boffset%5D=0&include=monetary_rewards,target&filter%5Bduplicate%5D=false&sort=submitted-desc'.format(self.bugcrowd_api_url, program),
                headers=self.get_headers(),
            )

        if response.ok:
            return response.json()
        else:
            raise Exception("Unable to get asset findings due to {} - {}".format(
                response.status_code, response.content.decode("utf-8")
            ))

    def test_connection(self):
        # Request programs
        response_programs = self.session.get(
            url='{}/programs'.format(self.bugcrowd_api_url),
            headers=self.get_headers(),
        )

        # Request assets to validate the org token
        response_subs = self.session.get(
            url='{}/submissions'.format(self.bugcrowd_api_url),
            headers=self.get_headers(),
        )

        if response_programs.ok and response_subs.ok:
            data = response_programs.json().get('data')
            progs = list(filter(lambda prog: prog["type"] == "program", data))
            program_names = ', '.join(list(map(lambda p: p["attributes"]["name"], progs)))
            return f'You have access to the "{ program_names }" programs'
        else:
            raise Exception("Connection failed (error: {} - {})".format(
                response_assets.status_code, response_assets.content.decode("utf-8")
            ))

    def test_product_connection(self, api_scan_configuration):
        submissions = self.get_findings(api_scan_configuration.service_key_1, api_scan_configuration.service_key_2)
        submission_number = len(submissions['data'])
        return f'You have access to "{submission_number}" submissions in Bugcrowd in the Program code "{api_scan_configuration.service_key_1}" and Target "{api_scan_configuration.service_key_2}" (leave service key 2 empty to get all submissions in program)'

    def get_headers(self):
        headers = {
            'Accept': 'application/vnd.bugcrowd+json',
            'Authorization': 'Token {}'.format(self.api_token),
            'User-Agent': 'DefectDojo',
            'Bugcrowd-Version': '2021-10-28'
        }

        return headers
