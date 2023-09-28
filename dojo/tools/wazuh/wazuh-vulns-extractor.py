import requests
from requests.auth import HTTPBasicAuth
import json
import urllib3

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Wazuh
BASE_URL = "https://<wazuh-ip-or-url>:55000"
AUTH_URL = f"{BASE_URL}/security/user/authenticate?raw=true"
HEADERS = {}

# Basic authentication creds
USERNAME = '<wazuh-api-user>'
PASSWORD = '<wazuh-api-pass>'

"""
Using Two Groups for Wazuh Agent Queries:

- Provides precise targeting by intersecting two specific groups, even if agents belong to multiple groups.
- Balances between broad and narrow agent selections.
- If narrow targeting isn't desired, set both group variables to the same name for a wider selection.
- Additionally, it appends an 'agent_ip' field for every vulnerability. This is later processed by DefectDojo to create endpoints and correlate each vulnerability to a specific agent, enhancing traceability and accountability.

Note: This approach refines the vulnerability reporting process by correlating agents with vulnerabilities more efficiently.
"""


GROUP_1 = "<group1-name>"
GROUP_2 = "<group2-name>"

# Authenticate and set token


def authenticate():
    response = requests.get(AUTH_URL, auth=HTTPBasicAuth(
        USERNAME, PASSWORD), verify=False)
    if response.status_code == 200:
        token = response.text
        HEADERS['Authorization'] = f'Bearer {token}'
    else:
        raise ValueError(
            f"Failed to authenticate. Status code: {response.status_code}, Detail: {response.text}")

# Retrieve agents for a specific group


def get_agents_in_group(group_name):
    endpoint = f"{BASE_URL}/groups/{group_name}/agents"
    response = requests.get(endpoint, headers=HEADERS, verify=False)
    if response.status_code == 200:
        return response.json()['data']['affected_items']
    else:
        print(
            f"Failed to retrieve agents for group {group_name}. Status code: {response.status_code}, Detail: {response.text}")
        return []

# Retrieve vulnerabilities for a specific agent


def get_vulnerabilities_for_agent(agent_id):
    endpoint = f"{BASE_URL}/vulnerability/{agent_id}"
    response = requests.get(endpoint, headers=HEADERS, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        print(
            f"Failed to retrieve vulnerabilities for agent {agent_id}. Status code: {response.status_code}, Detail: {response.text}")
        return None

# Main function


def main():
    authenticate()

    group1_agents = get_agents_in_group(GROUP_1)
    group2_agents = get_agents_in_group(GROUP_2)

    # Extract the agent IDs and IPs from the response for each group
    group1_agents_data = {agent['id']: agent['ip'] for agent in group1_agents}
    group2_ids = set(agent['id'] for agent in group2_agents)

    # Find the intersection of the two sets
    common_ids = set(group1_agents_data.keys()).intersection(group2_ids)

    vulnerabilities_list = []

    # Loop through each agent_id and get its vulnerabilities
    for agent_id in common_ids:
        vulnerabilities = get_vulnerabilities_for_agent(agent_id)
        if vulnerabilities:
            filtered_vulnerabilities = []
            # Extend the vulnerabilities with agent_ip field
            for vulnerability in vulnerabilities.get("data", {}).get("affected_items", []):
                # Skip the vulnerability if its condition is "Package unfixed"
                if vulnerability.get("condition") != "Package unfixed":
                    vulnerability["agent_ip"] = group1_agents_data[agent_id]
                    filtered_vulnerabilities.append(vulnerability)
            if filtered_vulnerabilities:
                vulnerabilities["data"]["affected_items"] = filtered_vulnerabilities
                vulnerabilities_list.append(vulnerabilities)

    # Write the filtered vulnerabilities to a JSON file
    with open("vulnerabilities.json", "w") as f:
        json.dump(vulnerabilities_list, f, indent=4)


if __name__ == "__main__":
    main()
