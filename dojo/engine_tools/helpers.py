# Utils
import random
from django.db.models import QuerySet, Q
from django.utils import timezone
from enum import Enum
from datetime import timedelta

# Dojo
from dojo.models import Finding
from dojo.engine_tools.models import FindingExclusion


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
    risk_score = random.randint(0, 100)

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
    
    Finding.objects.bulk_update(finding_list, ['priority'])     
    FindingExclusion.objects.bulk_create(finding_exclusion_list)
            
    return len(finding_exclusion_list)


def check_priorization():
    # Get all vulnerabilities
    
    all_vulnerabilities = Finding.objects.filter(
        active=True,
        tags__name__in=["prisma", "tenable"]
    )
    
    # Identify critical vulnerabilities
    blacklist_new_items = identify_critical_vulnerabilities(all_vulnerabilities)
    
    return {
        "message": f"{blacklist_new_items} added to blacklist"
    }
