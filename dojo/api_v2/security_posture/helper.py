import logging
from django.utils import timezone
from dojo.models import GeneralSettings
from dojo.api_v2.utils import http_response
from dojo.models import Engagement
logger = logging.getLogger(__name__)

def calculate_posture(result):
    posture_status_dict = GeneralSettings.get_value("SECURITY_POSTURE_STATUS", {})
    for key, value in posture_status_dict.items():
        if result <= value:
            return key 
    return list(posture_status_dict.keys())[-1] if posture_status_dict else "UNKNOWN"


def calculate_priority(findings):
    sum_priority = 0
    for finding in findings:
        sum_priority += finding.priority
    return round(sum_priority, 3)

def is_in_hacking_continuous(test, data):
    is_in_hacking_continuous = (
        set(test.tags.all().values_list("name", flat=True)) & 
        (set(GeneralSettings.get_value("HACKING_CONTINUOUS_TAGS", [])))
    )
    if is_in_hacking_continuous:
        present_day = timezone.now() 
        days_difference = (present_day - test.updated).days
        days_tolerance = GeneralSettings.get_value("HACKING_CONTINUOUS_DAYS_TOLERANCE", 30)
        latest_report_hacking = days_difference <= days_tolerance
        if latest_report_hacking:
            return True
        else:
            detail = ("SECURITY POSTURE: Test %s has Hacking Continuous tag but last update is older than %s days", 
                      test.id,
                      days_tolerance)
            logger.info(detail)
            data["details"].append(detail)
    return False


def adoption_devsecops_include(tags):
    tags = list(set(tags))
    return [tag for tag in tags if tag in GeneralSettings.get_value("DEVSECOPS_ADOPTION_INCLUDE_TAGS", ["engine_iac", "engine_container"])]


def get_security_posture(engagement: Engagement, engagement_name: str):
    data = {} 
    try:
        if isinstance(engagement, Engagement):
            pass
        elif isinstance(engagement_name, Engagement):
            engagement = engagement_name
        
    except Engagement.DoesNotExist:
        return http_response.not_found(
            message="Engagement not found", data={})

    data["engagement_name"] = engagement.name
    data["engagement_id"] = engagement.id
    data["severity_product"] = engagement.product.business_criticality
    data["is_in_hacking_continuos"] = False 
    data["details"] = []
    data["events_active_hacking"] = {"status": False, "events": []}
    tags = []
    for test in engagement.test_set.all():
        if is_in_hacking_continuous(test, data) and not data["is_in_hacking_continuos"]:
            data["is_in_hacking_continuos"] = True
        tags.extend(test.tags.all().values_list("name", flat=True))

    data["adoption_devsecops"] = adoption_devsecops_include(tags)
    active_finding = engagement.get_all_finding_active.only(
        "id",
        "severity",
        "priority",
        "tags"
    )
    data["counter_active_findings"] = active_finding.distinct().count() 
    data["counter_findings_by_priority"] = {
        "very_critical": 0,
        "critical": 0,
        "high": 0,
        "medium_low": 0,
        "unknown": 0,
    }
    data["counter_findings_by_severity"] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
    }
    for finding in active_finding.iterator():
        priority = finding.priority_classification
        logger.debug(f"Finding {finding.id} has priority {priority}")
        data["counter_findings_by_priority"][str(priority).lower().replace(" ", "_")] += 1
        data["counter_findings_by_severity"][str(finding.severity).lower()] += 1 
    events = active_finding.filter(
        active=True,
        is_mitigated=False,
        tags__name__in=GeneralSettings.get_value("HACKING_CONTINUOUS_EVENT_TAGS", [])
    )
    for event in events:
        data["events_active_hacking"]["status"] = True
        data["events_active_hacking"]["events"].append({
            "id": event.id,
            "name": event.title,
            "description": event.description,
        })


    data["result"] = calculate_priority(active_finding)
    data["status"] = calculate_posture(data["result"])
    return data
