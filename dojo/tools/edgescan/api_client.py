import requests
import json
from json.decoder import JSONDecodeError

from dojo.models import Tool_Configuration, Tool_Type


class EdgescanAPI(object):
    """
    A simple client for the Edgescan API
    """

    DEFAULT_URL = "https://live.edgescan.com"

    def __init__(self, tool_config=None):
        tool_type, _ = Tool_Type.objects.get_or_create(name='Edgescan')

        if not tool_config:
            try:
                tool_config = Tool_Configuration.objects.get(tool_type=tool_type)
            except Tool_Configuration.DoesNotExist:
                raise Exception(
                    'No Edgescan tool is configured. \n'
                    'Create a new Tool at Settings -> Tool Configuration'
                )
            except Tool_Configuration.MultipleObjectsReturned:
                raise Exception(
                    'More than one Tool Configuration for Edgescan exists. \n'
                    'Please specify at Product configuration which one should be used.'
                )

        if tool_config.authentication_type == "API":
            self.api_key = tool_config.api_key
            self.url = tool_config.url or self.DEFAULT_URL
            self.options = self.get_extra_options(tool_config)
        else:
            raise Exception('Edgescan Authentication type {} not supported'.format(tool_config.authentication_type))

    @staticmethod
    def get_extra_options(tool_config):
        if tool_config.extras:
            try:
                return json.loads(tool_config.extras)
            except (JSONDecodeError, TypeError):
                raise ValueError('JSON not provided in Extras field.')

    def get_findings(self, asset_ids):
        url = f"{self.url}/api/v1/vulnerabilities/export.json?c[asset_id_in]={asset_ids}&c[status]=open"
        if self.options and 'date' in self.options:
            url += f"&c[date_opened_after]={self.options['date']}"

        response = requests.get(
            url=url,
            headers=self.get_headers(),
            proxies=self.get_proxies(),
        )
        response.raise_for_status()
        return response.json()

    def get_headers(self):
        headers = {
            "X-API-TOKEN": self.api_key,
            "Content-Type": "application/json",
            "User-Agent": "DefectDojo",
        }

        return headers

    def get_proxies(self):
        if self.options and "proxy" in self.options:
            return {"https": self.options["proxy"]}

        return None
