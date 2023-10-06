import requests
import logging
import json
from django.core.exceptions import ValidationError
from dojo.models import Product_API_Scan_Configuration

logging.basicConfig(level=logging.WARNING)
"""
Step 1: Obtain a Wazuh JWT token and export it to an env var
$ TOKEN=$(curl -u <user>:<password> -k -X POST "https://localhost:55000/security/user/authenticate?raw=true")

Step 2: Increase the JWT token expiration time to 3 months (default is 900 seconds)
$ curl -k -X PUT "https://localhost:55000/security/config" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"auth_token_exp_timeout":7889231}'

Note: After changing the expiration time, all previously issued tokens will be revoked.

Step 3: Obtain a new JWT token with the updated expiration time.
$ curl -u <user>:<password> -k -X POST "https://localhost:55000/security/user/authenticate?raw=true"
"""


class WazuhAPI:
    def __init__(self, tool_config):
        self.base_url = tool_config.url
        self.headers = {}

        extras = tool_config.extras
        if extras and isinstance(extras, str):
            try:
                extras = json.loads(extras)
            except json.JSONDecodeError:
                raise ValueError(f"Failed to decode extras field as JSON: {extras}")
        elif extras and not isinstance(extras, dict):
            raise ValueError(f"Unexpected type for extras field: {type(extras)}")

        self.token = tool_config.api_key  # Add Wazuh JWT token as tool API key
        self.verify_ssl = (
            extras.get("verify_ssl", True) if extras else True
        )  # Default to True, but can be overridden in the tool configuration extras with {"verify_ssl": false}

        self.headers["Authorization"] = f"Bearer {self.token}"

    def get_agents_in_group(self, group_name):
        endpoint = f"{self.base_url}/groups/{group_name}/agents"
        response = requests.get(endpoint, headers=self.headers, verify=self.verify_ssl)
        response.raise_for_status()

        if response.ok:
            return response.json()["data"]["affected_items"]
        else:
            logging.warning(
                f"Failed to retrieve agents for group {group_name}. Status code: {response.status_code}, Detail: {response.text}"
            )
            return []

    def get_vulnerabilities_for_agent(self, agent_id):
        endpoint = f"{self.base_url}/vulnerability/{agent_id}"
        response = requests.get(endpoint, headers=self.headers, verify=self.verify_ssl)
        if response.status_code == 200:
            return response.json()
        else:
            logging.warning(
                f"Failed to retrieve vulnerabilities for agent {agent_id}. Status code: {response.status_code}, Detail: {response.text}"
            )
            return None

    def get_vulnerable_agents(self, GROUP_1, GROUP_2):
        group1_agents = self.get_agents_in_group(GROUP_1)
        group2_agents = self.get_agents_in_group(GROUP_2)

        group1_agents_data = {agent["id"]: agent["ip"] for agent in group1_agents}
        group2_ids = set(agent["id"] for agent in group2_agents)

        common_ids = set(group1_agents_data.keys()).intersection(group2_ids)

        vulnerabilities_list = []

        for agent_id in common_ids:
            vulnerabilities = self.get_vulnerabilities_for_agent(agent_id)
            if vulnerabilities:
                filtered_vulnerabilities = []
                for vulnerability in vulnerabilities.get("data", {}).get(
                    "affected_items", []
                ):
                    if vulnerability.get("condition") != "Package unfixed":
                        vulnerability["agent_ip"] = group1_agents_data[agent_id]
                        filtered_vulnerabilities.append(vulnerability)
                if filtered_vulnerabilities:
                    vulnerabilities["data"]["affected_items"] = filtered_vulnerabilities
                    vulnerabilities_list.append(vulnerabilities)

        return vulnerabilities_list
