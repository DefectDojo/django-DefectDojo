import vulners


class VulnersAPI:
    """
    A simple client for the Vulners API
    """

    vulners_api_url = None
    api_key = None

    def __init__(self, tool_config):
        if tool_config.authentication_type == "API":
            self.api_key = tool_config.api_key
            if tool_config.url:
                self.vulners_api_url = tool_config.url
        else:
            raise Exception('Vulners.com Authentication type {} not supported'.format(tool_config.authentication_type))

    def get_client(self):
        return vulners.VulnersApi(
            api_key=self.api_key,
            server_url=self.vulners_api_url,
            persistent=False
        )

    def get_findings(self):
        client = self.get_client()
        return client.vulnslist_report(limit=10000)

    def get_vulns_description(self, vulns_id):
        client = self.get_client()
        return client.get_multiple_bulletins(id=vulns_id, fields=['description', 'cwe', 'references', 'cvelist', 'cvss3'])
