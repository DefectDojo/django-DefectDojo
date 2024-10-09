from datetime import datetime

import cvss


def parse_ptart_severity(severity):
    severity_mapping = {
        1: "Critical",
        2: "High",
        3: "Medium",
        4: "Low"
    }
    return severity_mapping.get(severity, "Info")  # Default severity

def parse_ptart_fix_effort(effort):
    effort_mapping = {
        1: "High",
        2: "Medium",
        3: "Low"
    }
    return effort_mapping.get(effort, None)

def parse_title_from_hit(hit):
    hit_title = hit.get("title", None)
    hit_id = hit.get("id", None)

    if hit_title and hit_id:
        return f"{hit_id}: {hit_title}"
    return (hit_title or hit_id) or "Unknown Hit"


def parse_date_added_from_hit(hit):
    PTART_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
    date_added = hit.get("added", None)
    return parse_date(date_added, PTART_DATETIME_FORMAT)

def parse_date(date, format):
    try:
        if date:
            return datetime.strptime(date, format)
        else:
            return datetime.now()
    except ValueError:
        return datetime.now()

def parse_cvss_vector(hit, cvss_type):
    cvss_vector = hit.get("cvss_vector", None)
    # Defect Dojo Only supports CVSS v3 for now.
    if cvss_vector:
        if cvss_type == 3:
            try:
                c = cvss.CVSS3(cvss_vector)
                return c.clean_vector()
            except cvss.CVSS3Error:
                return None
        else:
            return None
    return None

def parse_retest_fix_status(status):
    fix_status_mapping = {
        'F': 'Fixed',
        'NF': 'Not Fixed',
        'PF': 'Partially Fixed',
        'NA': 'Not Applicable',
        'NT': 'Not Tested'
    }
    return fix_status_mapping.get(status, None)