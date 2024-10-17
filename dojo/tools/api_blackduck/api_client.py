from blackduck import Client


class BlackduckAPI:

    """A simple client for the BlackDuck API"""

    def __init__(self, tool_config):
        if tool_config.authentication_type == "API":
            self.api_token = tool_config.api_key
            self.base_url = tool_config.url
            self.client = Client(
                base_url=tool_config.url,
                token=tool_config.api_key,
                timeout=120,
            )
        else:
            msg = f"Authentication type {tool_config.authentication_type} not supported"
            raise ValueError(msg)

    # TODO: tests should be implemented here
    # def test_connection(self):
    #     response = ...
    #     if not response.ok:
    #         raise Exception(f'Unable to connect and search in BlackDuck due to ...')
    #     return f'You have access to ... projects'
    #
    # def test_product_connection(self, api_scan_configuration):
    #     response = ...
    #     if not response.ok:
    #         raise Exception(f'Unable to connect and search in BlackDuck due to ...')
    #     return f'You have access to project "..."'

    def get_project_by_name(self, project_name):
        for project in self.client.get_resource("projects"):
            if project["name"] == project_name:
                return project
        return None

    def get_version_by_name(self, project, version_name):
        for version in self.client.get_resource("versions", project):
            if version["versionName"] == version_name:
                return version
        return None

    def get_vulnerable_bom_components(self, version):
        return self.client.get_resource("vulnerable-components", version)

    def get_vulnerabilities(self, component):
        return self.client.get_json(
            f'/api/vulnerabilities/{component["vulnerabilityWithRemediation"]["vulnerabilityName"]}',
        )
