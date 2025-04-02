import logging
from django.conf import settings
import requests
import re

logger = logging.getLogger(__name__)

def mark_as_false_positive_semgrep(finding):
    try:
        semgrep_finding_id = re.search("[0-9]+" ,re.search( "Semgrep ID.*$", finding.description,flags=re.MULTILINE).group(0)).group(0)
    except Exception as e:
        logger.error("could not retrieve semgrep finding id while marking as false positive")
        logger.error(f"old_finding description: {finding.description}")
        logger.error(e)
        return
    url = "https://semgrep.dev/api/v1/deployments/creditas/triage"
    params = {"issue_type": finding.test.engagement.name, "new_triage_state": "ignored", "new_triage_reason": "false_positive", "issue_ids": semgrep_finding_id}
    headers = {
        'Accept': 'application/json',
        'Authorization': f'Bearer {settings.SEMGREP_TOKEN}'
    }
    try:
        response = requests.request("POST", url, headers=headers, params=params)
        if response.status_code != 200:
            logger.error(f"semgrep api returned status code {response.status_code}")
            logger.error(response.text)
    except Exception as e:
        logger.error("error sending false positive triage request to semgrep api")
        logger.error(e)
        return
