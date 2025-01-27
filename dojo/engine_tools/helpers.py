# Utils
from django.db import transaction
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from celery.utils.log import get_task_logger
from enum import Enum
from datetime import timedelta
from io import StringIO
import csv
import requests

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


def has_valid_comments(finding_exclusion, user) -> bool:    
    for comment in finding_exclusion.discussions.all():
        if comment.author == user:
            return True
        
    return False


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
    
    devsecops_email = cyber_providers.get("devsecops", "")
    
    title = f"Eligibility Assessment Vulnerability Whitelist - {finding_exclusion.unique_id_from_tool}"
    description = f"Eligibility Assessment Vulnerability Whitelist - {finding_exclusion.unique_id_from_tool}."
    
    email_notification_manager.send_mail_notification(
        event="finding_exclusion_request",
        user=None,
        title=title,
        description=description,
        url=reverse("finding_exclusion", args=[str(finding_exclusion.pk)]),
        recipient=[recipient, devsecops_email]
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
                description=f"All findings whitelisted via this finding exclusion {expired_fex.unique_id_from_tool} will be removed from the whitelist.",
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
    
    
def get_resource_type(finding) -> str:
    contains_host = any('hosts' in tag.name for tag in finding.tags.all())
    contains_ecr = any('images' in tag.name for tag in finding.tags.all())
    contains_lambda = any('lambdas' in tag.name for tag in finding.tags.all())
    
    if contains_host:
        return "host"
    if contains_ecr:
        return "image"
    if contains_lambda:
        return "function"
    
    return ""
    

def get_risk_score(finding) -> int:
    auth = (settings.TWISTLOCK_ACCESS_KEY, settings.TWISTLOCK_SECRET_KEY)
    api_url = settings.TWISTLOCK_API_URL % f"?cve={finding.cve}"
    try:
        vulnerabilities_response = requests.get(api_url, auth=auth, stream=True)
        vulnerabilities_response.raise_for_status()
        
        csv_file = StringIO(vulnerabilities_response.text)
        reader = csv.DictReader(csv_file)
        
        resource_type = get_resource_type(finding)
        
        for row in reader:
            if row.get("Impacted resource type") == resource_type:
                try:
                    risk_score = int(row.get("Highest risk score"))
                    return risk_score if risk_score else 0
                except Exception:
                    return 0
    except requests.exceptions.RequestException as e:
        logger.error(f"Error on twistlock api request: {e}")


def calculate_vulnerability_priority(finding) -> float:
    """
    Calculates the prioritization of a vulnerability with specific weights.
    
    Weights:
    - Risk Score: 0.4
    - EPSS: 0.4
    - Severity: 0.1
    - CVSS: 0.1
    
    Args:
        finding (Finding): Vulnerability object from the Django model
    
    Returns:
        float: Total prioritization score
    """
    # Initial validations
    if not finding.cve:
        return 0.0

    # Severity (25-100)
    severity_map = {
        'Low': 25,
        'Medium': 50,
        'High': 75,
        'Critical': 100
    }
    severity_score = severity_map.get(finding.severity, 0)

    # Risk Score (0-100)
    risk_score = get_risk_score(finding) or 1
    
    # CVSS Score (0-10 multiplied by 10)
    cvss_score = (finding.cvssv3_score or 0) * 10

    # EPSS Score (0-1 converted to 0-100)
    epss_score = (finding.epss_score or 0) * 100

    # Prioritization calculation with weights
    priorization_field_weights = settings.PRIORIZATION_FIELD_WEIGHTS
    
    priority = (
        (risk_score * priorization_field_weights.get("risk_score")) +     # Risk Score with weight 0.4
        (epss_score * priorization_field_weights.get("epss_score")) +     # EPSS with weight 0.4
        (severity_score * priorization_field_weights.get("severity_score")) + # Severity with weight 0.1
        (cvss_score * priorization_field_weights.get("cvss_score"))       # CVSS with weight 0.1
    )

    return round(priority, 2)


def identify_critical_vulnerabilities(findings) -> int:
    """
    Identifies vulnerabilities with a prioritization greater than 90 points.
    
    Args:
        findings (QuerySet): Set of vulnerabilities from the Finding model
    
    Returns:
        int: Number of critical vulnerabilities
    """
    finding_list = []
    finding_exclusion_list = []
    
    for finding in findings:
        priority = calculate_vulnerability_priority(finding)
        
        finding.priority = priority
        
        if priority > 90:
            finding_exclusion = FindingExclusion.objects.filter(unique_id_from_tool=finding.cve)
            finding.risk_status = "On Blacklist"
            finding.tags.add("black_list")
            
            if not finding_exclusion.exists():
                new_finding_exclusion = FindingExclusion(
                    type="black_list",
                    unique_id_from_tool=finding.cve,
                    expiration_date=timezone.now() + timedelta(days=int(settings.FINDING_EXCLUSION_EXPIRATION_DAYS)),
                    status_updated_at=None,
                    status_updated_by=None,
                    reviewed_at=None,
                    reason="Highly exploitable vulnerability.",
                    status="Accepted",
                    final_status="Accepted",
                    created_by=None
                )
                finding_exclusion_list.append(new_finding_exclusion)
        finding_list.append(finding)
    
    Finding.objects.bulk_update(finding_list, ["priority", "risk_status"])     
    FindingExclusion.objects.bulk_create(finding_exclusion_list)
            
    return len(finding_exclusion_list)


@app.task
def check_priorization():
    # Get all vulnerabilities
    
    all_vulnerabilities = Finding.objects.filter(
        active=True,
    ).filter(tag_filter).prefetch_related("tags")
    
    # Identify critical vulnerabilities
    blacklist_new_items = identify_critical_vulnerabilities(all_vulnerabilities)
    
    return {
        "message": f"{blacklist_new_items} added to blacklist"
    }