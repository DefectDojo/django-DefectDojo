from datetime import datetime

import cvss.parser


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

    try:
        if date_added:
            return datetime.strptime(date_added, PTART_DATETIME_FORMAT)
        else:
            return datetime.now()
    except ValueError:
        return datetime.now()


def parse_cvss_vector(hit, cvss_type):
    cvss_vector = hit.get("cvss_vector", None)
    # Dojo doesn't support CVSS 4.0 yet
    if cvss_vector and cvss_type < 4:
        vectors = cvss.parser.parse_cvss_from_text(cvss_vector)
        if len(vectors) > 0 and type(vectors[0]) == cvss.CVSS3:
            clean_vector = vectors[0].clean_vector()
            return clean_vector
    return None