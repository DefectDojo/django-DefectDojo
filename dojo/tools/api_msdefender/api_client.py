import requests


class MSDefenderAPI:
    """
    A simple client for the MS Defender Vulnerability API
    """

    def __init__(self, tool_config):
        if tool_config.authentication_type == "Password":
            self.user_name = tool_config.username
            self.password = tool_config.password
            self.base_url = "https://login.microsoftonline.com/%s/oauth2/token" % (tool_config.extras)
            body = {
                'resource': 'https://api.securitycenter.microsoft.com',
                'client_id': self.user_name,
                'client_secret': self.password,
                'grant_type': 'client_credentials'
            }
        else:
            raise ValueError(
                "Authentication type {} not supported".format(
                    tool_config.authentication_type
                )
            )
        response = requests.post(self.base_url, body)
        jsonResponse = response.json()
        self.aadToken = jsonResponse["access_token"]

    def get_findings(self):
        results = []
        vulnerabilities = []
        headers = {"Authorization": 'Bearer ' + self.aadToken}
        endpoint = "https://api.securitycenter.microsoft.com/api/vulnerabilities/machinesVulnerabilities"
        while True:
            response = requests.get(endpoint, headers=headers)
            if response.status_code == 200:
                json_output = response.json()
                if json_output["value"] == []:
                    break
                elif json_output.get("@odata.nextLink") is None:
                    vulnerabilities = vulnerabilities + json_output["value"]
                    break
                else:
                    vulnerabilities = vulnerabilities + json_output["value"]
                    endpoint = json_output["@odata.nextLink"]
            elif response.status_code == 429:  # "TooManyRequests"
                pass
            else:
                raise ConnectionError(
                    f'API might mot be avilable at the moment. {response.status_code} - {response.content.decode("utf-8")}'
                )
        results.append(vulnerabilities)
        machines = []
        endpoint = "https://api.securitycenter.microsoft.com/api/machines"
        while True:
            response = requests.get(endpoint, headers=headers)
            if response.status_code == 200:
                json_output = response.json()
                if json_output["value"] == []:
                    break
                elif json_output.get("@odata.nextLink") is None:
                    machines = machines + json_output["value"]
                    break
                else:
                    machines = machines + json_output["value"]
                    endpoint = json_output["@odata.nextLink"]
            elif response.status_code == 429:  # "TooManyRequests"
                pass
            else:
                raise ConnectionError(
                    f'API might mot be avilable at the moment. {response.status_code} - {response.content.decode("utf-8")}'
                )
        results.append(machines)
        return results
