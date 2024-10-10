import pathlib
from datetime import datetime

import cvss

from dojo.models import Endpoint


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
        "F": "Fixed",
        "NF": "Not Fixed",
        "PF": "Partially Fixed",
        "NA": "Not Applicable",
        "NT": "Not Tested"
    }
    return fix_status_mapping.get(status, None)


def parse_screenshots_from_hit(hit):
    if "screenshots" in hit:
        return [ss for ss in [parse_screenshot_data(screenshot) for screenshot in hit["screenshots"]] if ss is not None]
    else:
        return []


def parse_screenshot_data(screenshot):
    try:
        title = get_screenshot_title(screenshot)
        data = get_screenshot_data(screenshot)
        return {
            "title": title,
            "data": data
        }
    except ValueError:
        return None


def get_screenshot_title(screenshot):
    caption = screenshot.get('caption', 'screenshot') \
        if "caption" in screenshot and screenshot["caption"] \
        else "screenshot"
    title = f"{caption}{get_file_suffix_from_screenshot(screenshot)}"
    return title


def get_screenshot_data(screenshot):
    if "screenshot" in screenshot and "data" in screenshot["screenshot"] and screenshot["screenshot"]["data"]:
        return screenshot["screenshot"]["data"]
    else:
        raise ValueError("Screenshot data not found")


def get_file_suffix_from_screenshot(screenshot):
    if "screenshot" in screenshot and "filename" in screenshot['screenshot']:
        return pathlib.Path(screenshot['screenshot']['filename']).suffix
    else:
        return ""


def parse_attachment_from_hit(hit):
    if "attachments" in hit:
        return [f for f in [parse_attachment_data(attachment) for attachment in hit["attachments"]] if f is not None]
    else:
        return []


def parse_attachment_data(attachment):
    if "data" in attachment and attachment["data"]:
        return {
            "title": get_attachement_title(attachment),
            "data": attachment["data"]
        }
    else:
        # No data in attachment, let's not import this file.
        return None


def get_attachement_title(attachment):
    return attachment.get("title", "attachment") if "title" in attachment and attachment["title"] else "attachment"


def parse_endpoints_from_hit(hit):
    if "asset" in hit and hit["asset"]:
        endpoint = Endpoint.from_uri(hit["asset"])
        return [endpoint]
    else:
        return []


def generate_test_description_from_report_base(data):
    description = []
    if "executive_summary" in data and data["executive_summary"]:
        description.append(data["executive_summary"])
    if "engagement_overview" in data and data["engagement_overview"]:
        description.append(data["engagement_overview"])
    if "conclusion" in data and data["conclusion"]:
        description.append(data["conclusion"])
    return "\n\n".join(description) if description else None
