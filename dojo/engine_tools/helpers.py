# Utils
from django.db import transaction
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from celery.utils.log import get_task_logger
from enum import Enum

# Dojo
from dojo.models import Finding, Dojo_Group, Notes
from dojo.group.queries import get_group_members_for_group
from dojo.engine_tools.models import FindingExclusion
from dojo.engine_tools.queries import tag_filter
from dojo.celery import app
from dojo.user.queries import get_user
from dojo.notifications.helper import create_notification, EmailNotificationManger
from dojo.utils import get_full_url


logger = get_task_logger(__name__)

class Constants(Enum):
    VULNERABILITY_ID_HELP_TEXT = "Vulnerability technical id from the source tool. " \
                                 "Allows to track unique vulnerabilities."
    ON_WHITELIST = "On Whitelist"
    REVIEWERS_MAINTAINER_GROUP = settings.REVIEWER_GROUP_NAME
    APPROVERS_CYBERSECURITY_GROUP = settings.APPROVER_GROUP_NAME
    
    
def get_reviewers_members():
    reviewer_group = Dojo_Group.objects.filter(name=Constants.REVIEWERS_MAINTAINER_GROUP.value).first()
    reviewer_members = get_group_members_for_group(reviewer_group)
    
    return [member.user.username for member in reviewer_members if member]
    

def get_approvers_members():
    approvers_group = Dojo_Group.objects.filter(name=Constants.APPROVERS_CYBERSECURITY_GROUP.value).first()
    approvers_members = get_group_members_for_group(approvers_group)
    
    return [member.user.username for member in approvers_members if member]


def get_note(author, message):
    note, _ = Notes.objects.get_or_create(
        author=author,
        entry=message
    )
    return note


def send_mail_to_cybersecurity(finding_exclusion: FindingExclusion) -> None:
    email_notification_manager = EmailNotificationManger()
    recipient = None
    practice = finding_exclusion.practice
    
    cyber_providers = settings.PROVIDERS_CYBERSECURITY_EMAIL
    
    for key, value in cyber_providers.items():
        if key in practice:
            recipient = value
    
    if not recipient:
        return
        
    email_notification_manager.send_mail_notification(
        event="finding_exclusion_request",
        user=None,
        title=f"Eligibility Assessment Vulnerability Whitelist - {finding_exclusion.unique_id_from_tool}",
        description=f"Eligibility Assessment Vulnerability Whitelist - {finding_exclusion.unique_id_from_tool}.",
        url=reverse("finding_exclusion", args=[str(finding_exclusion.pk)]),
        recipient=recipient
    )


def remove_finding_from_whitelist(finding: Finding, note: Notes) -> Finding:
    finding.active = True
    finding.risk_status = None
    finding.notes.add(note)
    finding.tags.remove("white_list")
    
    return finding


def expire_finding_exclusion(expired_fex: FindingExclusion) -> None:
    try:
        with transaction.atomic():
            expired_fex.status = "Expired"
            expired_fex.save()
            system_user = get_user(settings.SYSTEM_USER)
            logger.info(f"Expired finding exclusion: {expired_fex}")
            note = get_note(system_user, "Finding has been removed from the whitelist as it has expired.")
            
            findings = Finding.objects.filter(
                cve=expired_fex.unique_id_from_tool,
                active=False,
                tags__name__icontains="white_list"
            ).prefetch_related("tags", "notes")
            
            findings_to_update = []
            
            for finding in findings:
                finding = remove_finding_from_whitelist(finding, note)
                findings_to_update.append(finding)
                logger.info(f"Removed finding {finding.id} from whitelist.")
            
            Finding.objects.bulk_update(findings_to_update, ["active", "risk_status"], 1000)
            
            maintainers = get_reviewers_members()
            approvers = get_approvers_members()
            
            create_notification(
                event="finding_exclusion_expired",
                title=f"The finding exclusion for {expired_fex.unique_id_from_tool} has expired.",
                description="All findings whitelisted via this finding exclusion will be removed from the whitelist.",
                url=reverse("finding_exclusion", args=[str(expired_fex.pk)]),
                recipients=maintainers + approvers + [expired_fex.created_by.username]
            )
    except Exception as e:
        logger.error(
            f"Error processing expired exclusion {expired_fex.uuid}: {str(e)}"
        )

@app.task
def expire_finding_exclusion_immediately(finding_exclusion_id: str) -> None:
    finding_exclusion = FindingExclusion.objects.get(uuid=finding_exclusion_id)
    expire_finding_exclusion(finding_exclusion)


@app.task
def check_expiring_findingexclusions():
    expired_finding_exclusions = FindingExclusion.objects.filter(
        type="white_list",
        status="Accepted",
        expiration_date__lt=timezone.now()
    )
    
    for expired_fex in expired_finding_exclusions:
        expire_finding_exclusion.apply_async(args=(str(expired_fex.uuid),))
        

@app.task
def add_findings_to_whitelist(unique_id_from_tool, relative_url):
    findings_to_update = Finding.objects.filter(
        cve=unique_id_from_tool,
        active=True
    ).filter(tag_filter)
    
    finding_exclusion_url = get_full_url(relative_url)
    system_user = get_user(settings.SYSTEM_USER)
    message = f"Finding added to white list, for more details check the finding exclusion request: {finding_exclusion_url}"
    note = get_note(system_user, message)
    
    for finding in findings_to_update:
        if 'white_list' not in finding.tags:
            finding.tags.add("white_list")
        finding.active = False
        finding.notes.add(note)
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