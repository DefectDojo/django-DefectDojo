# Utils
from django.db.models import QuerySet, Q
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from celery.utils.log import get_task_logger
from enum import Enum
from datetime import timedelta
import random

# Dojo
from dojo.models import Finding
from dojo.engine_tools.models import FindingExclusion
from dojo.engine_tools.queries import tag_filter
from dojo.celery import app
from dojo.notifications.helper import create_notification


logger = get_task_logger(__name__)

class Constants(Enum):
    VULNERABILITY_ID_HELP_TEXT = "Vulnerability technical id from the source tool. " \
                                 "Allows to track unique vulnerabilities."
    ON_WHITELIST = "On Whitelist"


@app.task
def check_expiring_findingexclusions():
    days_before_expiration = 5
    expiration_threshold = timezone.now() + timedelta(days=days_before_expiration)
    
    expiring_objects = FindingExclusion.objects.filter(
        expiration_date__lte=expiration_threshold,
        notification_sent=False
    ).exclude(status__in=['Accepted', 'Rejected'])
    
    for fex in expiring_objects:
        create_notification(
            event="other",
            title=f"{fex.unique_id_from_tool} | Whitelist request about to expire.",
            description=f"The request to whitelist {fex.unique_id_from_tool} expires on {fex.expiration_date.date()}, it is recommended to review the request as soon as possible.",
            url=reverse("finding_exclusion", args=[str(fex.pk)]),
        )
        
        fex.notification_sent = True
        fex.save()
        
        
@app.task
def add_findings_to_whitelist(unique_id_from_tool):
    findings_to_update = Finding.objects.filter(
        cve=unique_id_from_tool,
        active=True
    ).filter(tag_filter)
    
    for finding in findings_to_update:
        if 'white_list' not in finding.tags:
            finding.tags.add("white_list")
        finding.active = False
        finding.risk_status = Constants.ON_WHITELIST.value
        
    Finding.objects.bulk_update(findings_to_update, ["active", "risk_status"], 1000)
    logger.info(f"{findings_to_update.count()} findings added to whitelist.")
    

@app.task
def check_new_findings_to_whitelist():
    cves_on_whitelist = FindingExclusion.objects.filter(
        type="white_list", 
        status="Accepted"
    ).values_list("unique_id_from_tool", flat=True)
    
    findings_to_whitelist = Finding.objects.filter(
        cve__in=cves_on_whitelist,
        active=True,
    ).exclude(
        risk_status=Constants.ON_WHITELIST.value
    ).filter(tag_filter)
    
    for finding in findings_to_whitelist:
        if 'white_list' not in finding.tags:
            finding.tags.add("white_list")
        finding.active = False
        finding.risk_status = Constants.ON_WHITELIST.value
        
    Finding.objects.bulk_update(findings_to_whitelist, ["active", "risk_status"], 1000)
    logger.info(f"{findings_to_whitelist.count()} findings added to whitelist.")