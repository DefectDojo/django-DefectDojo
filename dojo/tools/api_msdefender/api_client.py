import json
import urllib.request
import urllib.parse
import requests
from dojo.utils import prepare_for_view


class MSDefenderAPI:
    """
    A simple client for the MS Defender Vulnerability API
    """

    def __init__(self, tool_config):
        if tool_config.authentication_type == "Password":
            self.base_url = "https://login.microsoftonline.com/%s/oauth2/token" % (tool_config.extras)
            body = {
                'resource': 'https://api.securitycenter.microsoft.com',
                'client_id': tool_config.username,
                'client_secret': prepare_for_view(tool_config.password),
                'grant_type': 'client_credentials'
            }
        else:
            raise ValueError(
                "Authentication type {} not supported".format(
                    tool_config.authentication_type
                )
            )
        data = urllib.parse.urlencode(body).encode("utf-8")
        req = urllib.request.Request(self.base_url, data)
        response = urllib.request.urlopen(req)
        jsonResponse = json.loads(response.read())
        self.aadToken = jsonResponse["access_token"]

    def get_findings(self):
        page = 0
        results = []
        while True:
            endpoint = 'https://api.securitycenter.microsoft.com/api/vulnerabilities/machinesVulnerabilities?$skip=' + str(page)
            headers = {"Authorization": 'Bearer ' + self.aadToken}
            json_output = requests.get(endpoint, headers=headers).json()
            if "error" in json_output:
                if json_output["error"]["code"] == "TooManyRequests":
                    print(json_output)
                    import time
                    time.sleep(60)
            else:
                results = results + json_output["value"]
                print(json_output['@odata.nextLink'])
            page += 10000
        return results
