from blackduck import Client


class BlackduckAPI:
    """
    A simple client for the BlackDuck API
    """

    def __init__(self, tool_config):
        if tool_config.authentication_type == "API":
            self.api_token = tool_config.api_key
            self.base_url = tool_config.url
            self.client = Client(base_url=tool_config.url, token=tool_config.api_key)
        else:
            raise ValueError(
                "Authentication type {} not supported".format(
                    tool_config.authentication_type
                )
            )

    def test_product_connection(self, api_scan_configuration):
        asset = self.get_asset(api_scan_configuration.service_key_1)
        asset_name = asset["resource"]["title"]
        api_scan_configuration.service_key_2 = asset_name
        api_scan_configuration.save()
        return f'You have access to asset "{asset_name}"'

    def get_project_by_name(self, project_name):
        for project in self.client.get_resource("projects"):
            if project["name"] == project_name:
                return project

    def get_version_by_name(self, project, version_name):
        for version in self.client.get_resource("versions", project):
            if version["versionName"] == version_name:
                return version

    def get_vulnerable_bom_components(self, version):
        return self.client.get_resource("vulnerable-components", version)

    def get_vulnerabilities(self, component):
        return self.client.get_json(
            f'/api/vulnerabilities/{component["vulnerabilityWithRemediation"]["vulnerabilityName"]}'
        )
