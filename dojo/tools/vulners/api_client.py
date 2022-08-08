import json

import requests


class VulnersAPI:
    """
    A simple client for the Cobalt.io API
    """

    vulners_api_url = "https://vulners.com"

    def __init__(self, tool_config):
        self.session = requests.Session()
        if tool_config.authentication_type == "API":
            self.api_key = tool_config.api_key
        else:
            raise Exception('Vulners.com Authentication type {} not supported'.format(tool_config.authentication_type))

    def get_findings(self):
        print(f'[Vulners API] get findings')
        response = self.session.post(
            url='{}/api/v3/reports/vulnsreport'.format(self.vulners_api_url),
            headers=self.get_headers(),
            json={
                'reporttype':'vulnslist',
                'skip':0,
                'size':10000,
                'apiKey':self.api_key
            }
        )

        if not response.ok:
            raise Exception("Unable to get Vulners report due to {} - {}".format(
                response.status_code, response.content.decode("utf-8")
            ))

        data = response.json()
        if data.get('result') == 'error':
            raise Exception("Unable to get Vulners report due to - {}".format(
                data.get('data', dict()).get('error')
            ))
        else:
            return data

    def get_vulns_description(self, vulns_id):
        """
        Get Extra information about provided vulnerabilities
        :param vulns_id: list Vulners vulnerabilities ID
        :return:
        """
        print(f'[Vulners API] get vulns description for {vulns_id}')
        response = self.session.post(
            url='{}/api/v3/search/id/'.format(self.vulners_api_url),
            headers=self.get_headers(),
            json={
                     'id': vulns_id,
                     'fields': ['description','cwe','enchantments','cvelist', 'cvss3'],
                     'apiKey':self.api_key
                 })

        if not response.ok:
            raise Exception("Unable to get Vulners report due to {} - {}".format(
                response.status_code, response.content.decode("utf-8")
            ))

        data = response.json()
        if data.get('result') == 'error':
            raise Exception("Unable to get Vulners report due to - {}".format(
                data.get('data', dict()).get('error')
            ))

        return data

    def get_headers(self):
        headers = {
            'User-Agent': 'DefectDojo',
        }

        return headers
