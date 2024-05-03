import requests
import json
from json.decoder import JSONDecodeError


class EdgescanAPI(object):
    """
    A simple client for the Edgescan API
    """

    DEFAULT_URL = "https://live.edgescan.com"

    def __init__(self, tool_config):
        if tool_config.authentication_type == "API":
            self.api_key = tool_config.api_key
            self.url = tool_config.url or self.DEFAULT_URL
            self.options = self.get_extra_options(tool_config)
        else:
            raise Exception(
                "Edgescan Authentication type {} not supported".format(
                    tool_config.authentication_type
                )
            )

    @staticmethod
    def get_extra_options(tool_config):
        if tool_config.extras:
            try:
                return json.loads(tool_config.extras)
            except (JSONDecodeError, TypeError):
                raise ValueError("JSON not provided in Extras field.")

    def get_findings(self, asset_ids):
        if asset_ids:
            url = f"{self.url}/api/v1/vulnerabilities/export.json?c[asset_id_in]={asset_ids}&c[status]=open"
        else:
            url = f"{self.url}/api/v1/vulnerabilities/export.json?c[status]=open"

        if self.options and "date" in self.options:
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
