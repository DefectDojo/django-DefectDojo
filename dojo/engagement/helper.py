import logging
from dojo.celery import app
from crum import get_current_user
from dojo.models import Engagement, Finding
from dojo.finding.helper import bulk_close_all_findings
logger = logging.getLogger(__name__)


@app.task
def close_all_finding_by_engagement(engagement_id: int):
    """
    Close all findings by engagement
    """
    try:
        user = get_current_user()
        findings = Finding.objects.filter(test__engagement=engagement_id,
                                          is_mitigated=False)
        logger.debug("CLOSE_ENGAGEMENT: "
                     f"number findings to be closed - {len(findings)}")
        bulk_close_all_findings(findings, user)

    except Engagement.DoesNotExist:
        logger.error("CLOSE_ENGAGEMENT:"
                     f"Engagement with id {engagement_id} does not exist.")
    except Exception as e:
        logger.error("CLOSE_ENGAGEMENT: "
                     f"An error occurred while closing findings: {e}")
