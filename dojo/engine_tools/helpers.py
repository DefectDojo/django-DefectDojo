# Utils
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from celery.utils.log import get_task_logger
from enum import Enum
from io import StringIO
from bs4 import BeautifulSoup
import csv
import requests

# Dojo
from dojo.models import Finding, Dojo_Group, Notes
from dojo.group.queries import get_group_members_for_group
from dojo.engine_tools.models import FindingExclusion, FindingExclusionDiscussion
from dojo.engine_tools.queries import tag_filter, blacklist_tag_filter
from dojo.celery import app
from dojo.user.queries import get_user
from dojo.notifications.helper import create_notification, EmailNotificationManger
from dojo.utils import get_full_url


logger = get_task_logger(__name__)

class Constants(Enum):
    VULNERABILITY_ID_HELP_TEXT = "Vulnerability technical id from the source tool. " \
                                 "Allows to track unique vulnerabilities."
    ON_WHITELIST = "On Whitelist"
    ON_BLACKLIST = "On Blacklist"
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
    if user.is_superuser:
        return True    
    for comment in finding_exclusion.discussions.all():
        if comment.author == user:
            return True
        
    return False


def send_mail_to_cybersecurity(finding_exclusion: FindingExclusion, message: str) -> None:
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
    
    title = message
    description = message
    
    email_notification_manager.send_mail_notification(
        event="finding_exclusion_request",
        subject=f"✅{message}",
        user=None,
        title=title,
        description=description,
        url=reverse("finding_exclusion", args=[str(finding_exclusion.pk)]),
        recipient=[recipient, devsecops_email]
    )
    

def remove_finding_from_list(finding: Finding, note: Notes, list_type: str) -> Finding:
    finding.risk_status = None
    finding.notes.add(note)
    
    if list_type == "white_list":
        if not finding.is_mitigated:
            finding.active = True
        finding.tags.remove("white_list")
    elif list_type == "black_list":
        finding.tags.remove("black_list")
    
    return finding


def expire_finding_exclusion(expired_fex: FindingExclusion) -> None:
    try:
        with transaction.atomic():
            expired_fex.status = "Expired"
            expired_fex.save()
            system_user = get_user(settings.SYSTEM_USER)
            logger.info(f"Expired finding exclusion: {expired_fex}")
            note = get_note(system_user, f"Finding has been removed from the {expired_fex.type} as it has expired.")
            
            is_active = True if expired_fex.type == "black_list" else False
            
            findings = Finding.objects.filter(
                Q(cve=expired_fex.unique_id_from_tool) | Q(vuln_id_from_tool=expired_fex.unique_id_from_tool),
                active=is_active,
                tags__name__icontains=expired_fex.type
            ).prefetch_related("tags", "notes")
            
            findings_to_update = []
            
            for finding in findings:
                finding = remove_finding_from_list(finding, note, expired_fex.type)
                findings_to_update.append(finding)
                logger.info(f"Removed finding {finding.id} from {expired_fex.type}.")
            
            Finding.objects.bulk_update(findings_to_update, ["active", "risk_status"], 1000)
            
            maintainers = get_reviewers_members()
            approvers = get_approvers_members()
            
            create_notification(
                event="finding_exclusion_expired",
                subject="⚠️Finding Exclusion Expired",
                title=f"The finding exclusion for {expired_fex.unique_id_from_tool} has expired.",
                description=f"All findings added via this finding exclusion {expired_fex.unique_id_from_tool} will be removed from the {expired_fex.type}.",
                url=reverse("finding_exclusion", args=[str(expired_fex.pk)]),
                recipients=maintainers + approvers + [expired_fex.created_by.username],
                icon="exclamation-triangle",
                color_icon="#FABC5C"
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
        status="Accepted",
        expiration_date__lt=timezone.now()
    )
    
    for expired_fex in expired_finding_exclusions:
        expire_finding_exclusion.apply_async(args=(str(expired_fex.uuid),))
        

@app.task
def add_findings_to_whitelist(unique_id_from_tool, relative_url):
    findings_to_update = Finding.objects.filter(
        Q(cve=unique_id_from_tool) | Q(vuln_id_from_tool=unique_id_from_tool),
        active=True
    ).exclude(
        risk_status=Constants.ON_WHITELIST.value
    ).filter(tag_filter)
    
    if findings_to_update.exists():
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
def check_new_findings_to_exclusion_list():
    finding_exclusions = FindingExclusion.objects.filter(
        status="Accepted"
    )
    
    for finding_exclusion in finding_exclusions:
        relative_url = reverse("finding_exclusion", args=[str(finding_exclusion.pk)])
        if finding_exclusion.type == "white_list":
            add_findings_to_whitelist.apply_async(args=(finding_exclusion.unique_id_from_tool, relative_url,))
        else:
            add_findings_to_blacklist.apply_async(args=(finding_exclusion.unique_id_from_tool, relative_url,))
    

@app.task
def add_findings_to_blacklist(unique_id_from_tool, relative_url, priority=90.0):
    findings_to_update = Finding.objects.filter(
        Q(cve=unique_id_from_tool) | Q(vuln_id_from_tool=unique_id_from_tool),
        active=True
    ).exclude(
        risk_status=Constants.ON_BLACKLIST.value
    ).filter(blacklist_tag_filter)
    
    if findings_to_update.exists():
        finding_exclusion_url = get_full_url(relative_url)
        system_user = get_user(settings.SYSTEM_USER)
        message = f"Finding added to blacklist, for more details check the finding exclusion request: {finding_exclusion_url}"
        note = get_note(system_user, message)
    
    for finding in findings_to_update:
        if 'black_list' not in finding.tags:
            finding.tags.add("black_list")
        finding.notes.add(note)
        finding.risk_status = Constants.ON_BLACKLIST.value
        finding.priority = priority
        
    Finding.objects.bulk_update(findings_to_update, ["risk_status", "priority"], 1000)
    findings_to_update_count = findings_to_update.count()
    logger.info(f"{findings_to_update_count} findings added to blacklist.")
    
    if findings_to_update_count > 0:
        blacklist_message = f"{findings_to_update_count} findings added to the blacklist. CVE: {unique_id_from_tool}."
        create_notification(
            event="finding_exclusion_request",
            subject="✅Findings added to blacklist",
            title=blacklist_message,
            description=blacklist_message,
            url=relative_url,
            recipients=get_reviewers_members() + get_approvers_members(),
            color_icon="#52A3FA"
        )
        finding_exclusion = FindingExclusion.objects.filter(
            unique_id_from_tool=unique_id_from_tool, 
            type="black_list", 
            status="Accepted"
        ).first()
        send_mail_to_cybersecurity(finding_exclusion, blacklist_message)


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
    api_url = settings.TWISTLOCK_API_URL + f"?cve={finding.cve}"
    try:
        vulnerabilities_response = requests.get(api_url, auth=auth, stream=True)
        vulnerabilities_response.raise_for_status()
        
        csv_file = StringIO(vulnerabilities_response.text)
        reader = csv.DictReader(csv_file)
        
        resource_type = get_resource_type(finding)
        
        for row in reader:
            if row.get("Impacted resource type") == resource_type:
                try:
                    risk_score = float(row.get("Highest risk score"))
                    if finding.cvssv3_score == 0:
                        finding.cvssv3_score = float(row.get("Highest CVSS", 0))
                    return risk_score if risk_score else 0
                except Exception:
                    return 0
    except requests.exceptions.RequestException as e:
        logger.error(f"Error on twistlock api request: {e}")


def get_tenable_risk_score(finding) -> int:
    if not finding.description:
        return 0
    
    soup = BeautifulSoup(finding.description, "html.parser")
    
    rating_label = soup.find("strong", string="Vulnerability Priority Rating:")
    
    if rating_label:
        rating_text = rating_label.find_parent("p").get_text(strip=True).split(":")[-1].strip()
        
        try:
            return int(rating_text)
        except ValueError:
            return 0
    
    return 0


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
    if "prisma" in finding.tags:
        risk_score = get_risk_score(finding) or 1
    elif "tenable" in finding.tags:
        risk_score = get_tenable_risk_score(finding) or 1
    else:
        risk_score = 1
    
    
    # CVSS Score (0-10 multiplied by 10)
    cvss_score = (finding.cvssv3_score or 0) * 10

    # EPSS Score (0-1 converted to 0-100)
    epss_score = (finding.epss_score or 0) * 100

    # Prioritization calculation with weights
    priorization_field_weights = settings.PRIORIZATION_FIELD_WEIGHTS
    
    priority = (
        (risk_score * float(priorization_field_weights.get("risk_score"))) +     # Risk Score with weight 0.4
        (epss_score * float(priorization_field_weights.get("epss_score"))) +     # EPSS with weight 0.4
        (severity_score * float(priorization_field_weights.get("severity_score"))) + # Severity with weight 0.1
        (cvss_score * float(priorization_field_weights.get("cvss_score")))       # CVSS with weight 0.1
    )

    return round(priority, 2)


def add_discussion_to_finding_exclusion(finding_exclusion) -> None:
    system_user = get_user(settings.SYSTEM_USER)
    content = "Created by the vulnerability prioritization check."
    
    discussion = FindingExclusionDiscussion(
        finding_exclusion=finding_exclusion,
        author=system_user,
        content=content
    )
    discussion.save()


def identify_critical_vulnerabilities(findings) -> int:
    """
    Identifies vulnerabilities with a prioritization greater than 90 points.
    
    Args:
        findings (QuerySet): Set of vulnerabilities from the Finding model
    
    Returns:
        int: Number of critical vulnerabilities
    """
    finding_exclusion_list = []
    system_user = get_user(settings.SYSTEM_USER)
    
    for finding in findings:
        priority = calculate_vulnerability_priority(finding)
        
        Finding.objects.filter(
            (Q(cve=finding.cve) & ~Q(cve=None)) | (Q(vuln_id_from_tool=finding.cve) & ~Q(vuln_id_from_tool=None)),
            active=True
        ).filter(
            blacklist_tag_filter
        ).update(priority=priority)
        
        if priority > int(settings.PRIORIZATION_FIELD_WEIGHTS.get("minimum_prioritization")):
            finding_exclusion = FindingExclusion.objects.filter(unique_id_from_tool=finding.cve, type="black_list", status="Accepted")
            
            if not finding_exclusion.exists():
                new_finding_exclusion = FindingExclusion(
                    type="black_list",
                    unique_id_from_tool=finding.cve,
                    expiration_date=None,
                    status_updated_at=timezone.now(),
                    status_updated_by=system_user,
                    reviewed_at=None,
                    reason="Highly exploitable vulnerability.",
                    status="Accepted",
                    final_status="Accepted",
                    created_by=system_user,
                    accepted_by=system_user
                    
                )
                finding_exclusion_list.append(new_finding_exclusion)
                relative_url = reverse("finding_exclusion", args=[str(new_finding_exclusion.pk)])
                add_findings_to_blacklist.apply_async(args=(new_finding_exclusion.unique_id_from_tool, relative_url, priority,))
            else:
                fx = finding_exclusion.first()
                relative_url = reverse("finding_exclusion", args=[str(fx.pk)])
                add_findings_to_blacklist.apply_async(args=(fx.unique_id_from_tool, relative_url, priority,))
        
    FindingExclusion.objects.bulk_create(finding_exclusion_list)
    
    for finding_exclusion in finding_exclusion_list:
        add_discussion_to_finding_exclusion(finding_exclusion)
            
    return len(finding_exclusion_list)


@app.task
def check_priorization():
    # Get all vulnerabilities
    
    all_vulnerabilities = (
        Finding.objects.filter(active=True)
        .filter(blacklist_tag_filter)
        .order_by("cve")
        .distinct("cve")
    )
    
    # Identify critical vulnerabilities
    blacklist_new_items = identify_critical_vulnerabilities(all_vulnerabilities)
    
    return {
        "message": f"{blacklist_new_items} added to blacklist"
    }


@app.task
def remove_findings_from_deleted_finding_exclusions(unique_id_from_tool: str, fx_type: str) -> None:
    try:
        with transaction.atomic():
            system_user = get_user(settings.SYSTEM_USER)
            note = get_note(system_user, f"Finding has been removed from the {fx_type} as it has deleted.")
            
            is_active = True if fx_type == "black_list" else False
            
            findings = Finding.objects.filter(
                Q(cve=unique_id_from_tool) | Q(vuln_id_from_tool=unique_id_from_tool),
                active=is_active,
                tags__name__icontains=fx_type
            ).prefetch_related("tags", "notes")
            
            findings_to_update = []
            
            for finding in findings:
                finding = remove_finding_from_list(finding, note, fx_type)
                findings_to_update.append(finding)
                logger.info(f"Removed finding {finding.id} from {fx_type}.")
            
            Finding.objects.bulk_update(findings_to_update, ["active", "risk_status"], 1000)
            
    except Exception as e:
        logger.error(
            f"Error processing deleted exclusion {unique_id_from_tool}: {str(e)}"
        )