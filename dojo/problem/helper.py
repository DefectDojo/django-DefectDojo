import json
import os
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from dojo.models import Problem, Finding

import logging
logger = logging.getLogger(__name__)

CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.json')
CACHED_JSON_FILE = os.path.join('/app/media', 'cached_disambiguator.json')

SEVERITY_ORDER = {
    'Critical': 5,
    'High': 4,
    'Medium': 3,
    'Low': 2,
    'Info': 1
}

def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

def validate_json(data):
    if not isinstance(data, dict):
        return False
    for key, value in data.items():
        if not isinstance(key, str) or not isinstance(value, list):
            return False
        if not all(isinstance(item, str) for item in value):
            return False
    return True

def download_json(json_url):
    response = requests.get(json_url, timeout=5, verify=False)
    response.raise_for_status()
    return response.json()

def load_cached_json():
    try:
        if os.path.exists(CACHED_JSON_FILE):
            with open(CACHED_JSON_FILE, 'r') as f:
                data = json.load(f)
                if validate_json(data):
                    return data
    except (ValueError, json.JSONDecodeError):
        pass 
    return None

def save_json_to_cache(data):
    logger.info('Saving disambiguator JSON to cache')
    with open(CACHED_JSON_FILE, 'w') as f:
        json.dump(data, f)

def load_json():
    try:
        # Disable SSL warnings
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        cached_data = load_cached_json()
        if cached_data:
            return cached_data

        # Cache is missing or invalid, download and validate
        config = load_config()
        json_url = config.get('json_url')

        if json_url:
            data = download_json(json_url)
            if validate_json(data):
                save_json_to_cache(data)
                return data

        return {}

    except (requests.RequestException, ValueError, json.JSONDecodeError) as e:
        logger.error('Error loading disambiguator JSON: %s', e)
        return {}

def extract_script_id(full_id):
    parts = full_id.split('____')
    return parts[0] if len(parts) == 2 else None

def find_or_create_problem(finding):
    data = load_json()
    script_id = finding.vuln_id_from_tool

    valid_ids_mapping = {
        key: [extract_script_id(full_id) for full_id in script_ids if extract_script_id(full_id)]
        for key, script_ids in data.items()
    }

    for key, valid_ids in valid_ids_mapping.items():
        if script_id in valid_ids:
            problem = _get_or_update_problem(valid_ids, finding, script_id)
            if problem:
                return problem

    # if the script_id is not in the mapping, create a new one
    return _get_or_create_problem_by_script_id(script_id, finding)

def _get_or_update_problem(valid_ids, finding, script_id):
    for valid_id in valid_ids:
        related_finding = Finding.objects.filter(vuln_id_from_tool=valid_id).first()
        if related_finding and related_finding.problem:
            problem = related_finding.problem
            if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[problem.severity]:
                _update_problem(problem, finding.title, finding.description, finding.severity)
            return problem

    return Problem.objects.create(
        name=finding.title,
        description=finding.description,
        severity=finding.severity
    )

def _get_or_create_problem_by_script_id(script_id, finding):
    related_finding = Finding.objects.filter(vuln_id_from_tool=script_id).first()
    if related_finding and related_finding.problem:
        problem = related_finding.problem
        if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[problem.severity]:
            _update_problem(problem, finding.title, finding.description, finding.severity)
        return problem

    return Problem.objects.create(
        name=finding.title,
        description=finding.description,
        severity=finding.severity
    )

def _update_problem(problem, name, description, severity):
    problem.name = name
    problem.description = description
    problem.severity = severity
    problem.save()
