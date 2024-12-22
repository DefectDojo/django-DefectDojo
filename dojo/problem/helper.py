import json
import os
import requests

from django.conf import settings

from dojo.models import Problem, Finding

import logging
logger = logging.getLogger(__name__)

MEDIA_ROOT = os.getenv('DD_MEDIA_ROOT', '/app/media')
CACHED_JSON_FILE = os.path.join(MEDIA_ROOT, 'cached_disambiguator.json')

SEVERITY_ORDER = {
    'Critical': 5,
    'High': 4,
    'Medium': 3,
    'Low': 2,
    'Info': 1
}

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

def mapping_script_problem_id(mappings_json_findings):
    script_to_problem_mapping = {
        script_id: key
        for key, script_ids in mappings_json_findings.items()
        for script_id in script_ids
    }
    return script_to_problem_mapping

def load_json(check_cash=True):
    try:
        if check_cash:
            cached_data = load_cached_json()
            if cached_data and validate_json(cached_data):
                return mapping_script_problem_id(cached_data)

        data = download_json(settings.PROBLEM_MAPPINGS_JSON_URL)
        if validate_json(data):
            save_json_to_cache(data)
            return mapping_script_problem_id(data)

    except (requests.RequestException, ValueError, json.JSONDecodeError) as e:
        logger.error('Error loading disambiguator JSON: %s', e)
        pass

    return {}

def find_or_create_problem(finding, script_to_problem_mapping):
    problem_id = script_to_problem_mapping.get(finding.vuln_id_from_tool)
    if problem_id:
        return _get_or_update_problem(finding, problem_id)

    # if the script_id is not in the mapping, create a new one
    return _get_or_create_problem_by_script_id(finding)

def _get_or_update_problem(finding, problem_id):
    problem = Problem.objects.filter(problem_id=problem_id).first()
    if problem:
        if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[problem.severity]:
            _update_problem(problem, finding.title, finding.severity)
        return problem

    return Problem.objects.create(
        name=finding.title,
        problem_id=problem_id,
        severity=finding.severity
    )

def _get_or_create_problem_by_script_id(finding):
    related_finding = Finding.objects.filter(vuln_id_from_tool=finding.vuln_id_from_tool).first()
    if related_finding and related_finding.problem:
        problem = related_finding.problem
        if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[problem.severity]:
            _update_problem(problem, finding.title, finding.severity)
        return problem

    return Problem.objects.create(
        name=finding.title,
        problem_id=finding.description,
        severity=finding.severity
    )

def _update_problem(problem, name, severity):
    problem.name = name
    problem.severity = severity
    problem.save()
