import requests
from urllib.parse import urlencode
from dojo.models import Tool_Type


class BugcrowdAPI:
    """
    A simple client for the bugcrowd.io API
    """

    bugcrowd_api_url = "https://api.bugcrowd.com"
    default_headers = {
            'Accept': 'application/vnd.bugcrowd+json',
            'User-Agent': 'DefectDojo',
            'Bugcrowd-Version': '2021-10-28'
                }

    def __init__(self, tool_config):
        tool_type, _ = Tool_Type.objects.get_or_create(name='Bugcrowd API')

        self.session = requests.Session()
        if tool_config.authentication_type == "API":
            self.api_token = tool_config.api_key
            self.session.headers.update({
                    "Authorization": 'Token {}'.format(self.api_token)})
            self.session.headers.update(self.default_headers)
        else:
            raise Exception('bugcrowd Authentication type {} not supported'.format(tool_config.authentication_type))

    def get_findings(self, program, target):
        """
        Returns the findings for a given bugcrowd program and target, if target is *, everything is returned
        :param program:
        :param target:
        :return:
        """
        output = {'data': []}
        params_default = {'filter[program]': program, 'page[limit]': 100, 'page[offset]': 0, 'include': 'monetary_rewards,target', 'filter[duplicate]': 'false', 'sort': 'submitted-desc'}

        if target:
            params = params_default
            params['filter[target]'] = target
            params_encoded = urlencode(params)
        else:
            params_encoded = urlencode(params_default)

        next = '{}/submissions?{}'.format(self.bugcrowd_api_url, params_encoded)
        while next != '':
            response = self.session.get(url=next)

            if response.ok:
                data = response.json()
                # When we hit the end of the submissions, break out
                if len(data['data']) == 0 or data['meta']['total_hits'] == data['meta']['count']:
                    output['data'] = output['data'] + data['data']
                    break

                print('Fetched ' + str(len(data['data'])) + ' submissions')
                output['data'] = output['data'] + data['data']

                # Otherwise, keep updating next link
                next = '{}{}'.format(self.bugcrowd_api_url, data["links"]["next"])
            else:
                next = 'over'
                raise Exception("Unable to get asset findings due to {} - {}".format(
                    response.status_code, response.content.decode("utf-8")))

        print('Total gathered submissions from Bugcrowd: ' + str(len(output['data'])))
        return output

    def test_connection(self):
        # Request programs
        response_programs = self.session.get(
            url='{}/programs'.format(self.bugcrowd_api_url))

        # Request assets to validate the org token
        response_subs = self.session.get(
            url='{}/submissions'.format(self.bugcrowd_api_url))

        if response_programs.ok and response_subs.ok:
            data = response_programs.json().get('data')
            progs = list(filter(lambda prog: prog["type"] == "program", data))
            program_names = ', '.join(list(map(lambda p: p["attributes"]["name"], progs)))
            return f'You have access to the "{ program_names }" programs'
        else:
            raise Exception("Connection failed (error: {} - {})".format(
                response_subs.status_code, response_subs.content.decode("utf-8")
            ))

    def test_product_connection(self, api_scan_configuration):
        submissions = self.get_findings(api_scan_configuration.service_key_1, api_scan_configuration.service_key_2)
        submission_number = len(submissions['data'])
        return f'You have access to "{submission_number}" submissions in Bugcrowd in the Program code "{api_scan_configuration.service_key_1}" and Target "{api_scan_configuration.service_key_2}" (leave service key 2 empty to get all submissions in program)'

    def get_headers(self):

        self.default_headers['Authorization'] = 'Token {}'.format(self.api_token)

        return self.default_headers
