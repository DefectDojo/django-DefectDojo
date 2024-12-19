import json
import os
from dojo.models import Problem, Finding

SEVERITY_ORDER = {
    'Critical': 5,
    'High': 4,
    'Medium': 3,
    'Low': 2,
    'Info': 1
}

JSON_FILE = os.path.join(os.path.dirname(__file__), 'disambiguator.json')

def load_json():
    with open(JSON_FILE, 'r') as f:
        return json.load(f)

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
