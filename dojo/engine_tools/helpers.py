# Utils
from django.db.models import QuerySet, Q
from django.utils import timezone
from django.urls import reverse
from enum import Enum
from datetime import timedelta
import random

# Dojo
from dojo.models import Finding
from dojo.engine_tools.models import FindingExclusion
from dojo.celery import app
from dojo.notifications.helper import create_notification


class Constants(Enum):
    VULNERABILITY_ID_HELP_TEXT = "Vulnerability technical id from the source tool. " \
                                 "Allows to track unique vulnerabilities."


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

    # Risk Score (0-100, random if it doesn't exist)
    risk_score = random.randint(95, 100)

    # CVSS Score (0-10 multiplied by 10)
    cvss_score = (finding.cvssv3_score or 0) * 10

    # EPSS Score (0-1 converted to 0-100)
    epss_score = (finding.epss_score or 0) * 100

    # Prioritization calculation with weights
    prioridad = (
        (risk_score * 0.4) +     # Risk Score with weight 0.4
        (epss_score * 0.4) +     # EPSS with weight 0.4
        (severity_score * 0.1) + # Severity with weight 0.1
        (cvss_score * 0.1)       # CVSS with weight 0.1
    )

    return round(prioridad, 2)


def identify_critical_vulnerabilities(findings: QuerySet) -> int:
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
                    expiration_date=timezone.now() + timedelta(days=90),
                    status_updated_at=None,
                    status_updated_by=None,
                    reviewed_at=None,
                    user_history=None,
                    product=None,
                    finding=None,
                    reason="Highly exploitable vulnerability.",
                    status="Accepted",
                    final_status="Accepted",
                    accepted_by=None,
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
    ).filter(
        Q(tags__name__icontains="prisma") | Q(tags__name__icontains="tenable")
    )
    
    # Identify critical vulnerabilities
    blacklist_new_items = identify_critical_vulnerabilities(all_vulnerabilities)
    
    return {
        "message": f"{blacklist_new_items} added to blacklist"
    }
    

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
    ).filter(
        Q(tags__name__icontains="prisma") | Q(tags__name__icontains="tenable")
    )
    
    for finding in findings_to_update:
        if not 'white_list' in finding.tags:
            finding.tags.add("white_list")
        finding.active = False
        finding.risk_status = "On Whitelist"
        
    Finding.objects.bulk_update(findings_to_update, ["active", "risk_status"], 1000)