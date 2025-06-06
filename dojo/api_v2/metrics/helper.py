import logging
from datetime import datetime
logger = logging.getLogger(__name__)


def add_findings_metrics(user_data,
                         status,
                         finding,
                         exclude_field):
    logger.debug(
        f"METRICS IA RECOMMENDATION: {finding.id} "
        f"with status {status} to user {user_data.get('username')}")

    if "findings" not in exclude_field:
        if finding_data := user_data["findings"].get(finding.id):
            finding_data["like"] = status
        else:
            finding_data = {
                "last_updated": finding.ia_recommendation["data"].get("last_modified", ""),
                "like": status,
                "engagement": finding.test.engagement.name,
                "product": finding.test.engagement.product.name,
                "product_type": finding.test.engagement.product.prod_type.name,
            }
            user_data["findings"][finding.id] = finding_data
    user_data["interaction_counter"] += 1
    user_data["like_counter"] += 1 if status is True else 0
    user_data["dislike_counter"] += 1 if status is False else 0

    return user_data


def apply_filter(finding, **kwargs):
    """
    Filters a finding based on the provided date range.
    Args:
        finding: The finding to filter.
        kwargs: Dictionary containing 'start_date' and/or 'end_date'.
    Returns:
        bool: True if the finding matches the filter criteria, False otherwise.
    """
    last_modified = finding.ia_recommendation["data"].get("last_modified", None)

    if not last_modified:
        return False

    try:
        last_modified_date = datetime.strptime(last_modified, "%Y-%m-%d").date()
    except ValueError:
        logger.error(f"Invalid date format for last_modified: {last_modified}")
        return False

    start_date = kwargs.get("start_date")
    end_date = kwargs.get("end_date")

    if start_date and end_date:
        return start_date <= last_modified_date <= end_date
    elif start_date:
        return last_modified_date >= start_date
    elif end_date:
        return last_modified_date <= end_date

    return True


def get_metrics_ia_recommendation(
        data,
        finding,
        flag_counter=True,
        exclude_field=[]):

    status = finding.ia_recommendation["data"].get("like_status", None)
    username = finding.ia_recommendation["data"].get("user", None)
    if user_data := data["users"].get(username):
        user_data = add_findings_metrics(
            user_data,
            status,
            finding,
            exclude_field)
    else:
        data["users"][username] = {
            "interaction_counter": 0,
            "like_counter": 0,
            "dislike_counter": 0,
            "findings": {}
        }
        data = get_metrics_ia_recommendation(
            data,
            finding,
            flag_counter=False,
            exclude_field=exclude_field)

    if flag_counter:
        data["interaction_counter"] += 1
        if status is True:
            data["like_counter"] += 1
        if status is False:
            data["dislike_counter"] += 1

    return data
