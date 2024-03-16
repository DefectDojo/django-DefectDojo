import requests


class CobaltAPI:
    """
    A simple client for the Cobalt.io API
    """

    cobalt_api_url = "https://api.cobalt.io"

    def __init__(self, tool_config):
        self.session = requests.Session()
        if tool_config.authentication_type == "API":
            self.api_token = tool_config.api_key
            self.org_token = tool_config.extras
        else:
            raise Exception(
                f"Cobalt.io Authentication type {tool_config.authentication_type} not supported"
            )

    def get_asset(self, asset_id):
        """
        Returns an asset
        :param asset_id:
        :return:
        """
        assets = self.get_assets()

        for asset in assets:
            if asset["resource"]["id"] == asset_id:
                return asset

        raise Exception(f"Asset {asset_id} not found in organisation")

    def get_assets(self):
        """Returns all org assets"""
        response = self.session.get(
            url=f"{self.cobalt_api_url}/assets?limit=1000",
            headers=self.get_headers(),
        )

        if response.ok:
            return response.json().get("data")
        else:
            raise Exception(
                "Unable to get assets due to {} - {}".format(
                    response.status_code, response.content.decode("utf-8")
                )
            )

    def get_findings(self, asset_id):
        """
        Returns the findings for an asset
        :param asset_id:
        :return:
        """
        response = self.session.get(
            url=f"{self.cobalt_api_url}/findings?limit=1000&asset={asset_id}",
            headers=self.get_headers(),
        )

        if response.ok:
            return response.json()
        else:
            raise Exception(
                "Unable to get asset findings due to {} - {}".format(
                    response.status_code, response.content.decode("utf-8")
                )
            )

    def test_connection(self):
        # Request orgs for the org name
        response_orgs = self.session.get(
            url=f"{self.cobalt_api_url}/orgs",
            headers=self.get_headers(),
        )

        # Request assets to validate the org token
        response_assets = self.session.get(
            url=f"{self.cobalt_api_url}/assets",
            headers=self.get_headers(),
        )

        if response_orgs.ok and response_assets.ok:
            data = response_orgs.json().get("data")
            orgs = filter(
                lambda org: org["resource"]["token"] == self.org_token, data
            )
            org = list(orgs)[0]
            org_name = org["resource"]["name"]
            return f'You have access to the "{org_name}" organization'
        else:
            raise Exception(
                "Connection failed (error: {} - {})".format(
                    response_assets.status_code,
                    response_assets.content.decode("utf-8"),
                )
            )

    def test_product_connection(self, api_scan_configuration):
        asset = self.get_asset(api_scan_configuration.service_key_1)
        asset_name = asset["resource"]["title"]
        api_scan_configuration.service_key_2 = asset_name
        api_scan_configuration.save()
        return f'You have access to asset "{asset_name}"'

    def get_headers(self):
        headers = {
            "accept": "application/vnd.cobalt.v1+json",
            "Authorization": f"Bearer {self.api_token}",
            "User-Agent": "DefectDojo",
        }

        if self.org_token is not None:
            headers["X-Org-Token"] = self.org_token

        return headers
