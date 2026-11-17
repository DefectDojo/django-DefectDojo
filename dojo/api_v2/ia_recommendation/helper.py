import logging
import requests
import json
import dojo.finding.helper as finding_helper
from django.utils import timezone
from typing import List
from dojo.celery import app
from django.shortcuts import get_object_or_404
from dojo.models import Finding
from dojo.models import GeneralSettings
from dojo.api_v2.ia_recommendation.serializers import IaRecommendationSerializer
from dojo.api_v2.utils import http_response
from django.conf import settings


logger = logging.getLogger(__name__)

@app.task
def async_get_ia_recommendation(fid, user, save=True):
    version = GeneralSettings.get_value("HOST_IA_RECOMMENDATION_VERSION", "v1")
    error_response = {
    "status": "Ok",
    "ia_recommendations": (
            "At the moment, you can't generate a recommendation for this finding.\n"
            "Please try again later or with a different finding.ðŸ«£"
        )}
    url = GeneralSettings.get_value("HOST_IA_RECOMMENDATION")
    params = {
        "grant_type": "client_credentials",
        "client_id" : settings.CLIENT_ID_IA,
        "client_secret": settings.CLIENT_SECRET_IA
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    logger.debug("IA RECOMMENDATION:get token by finding: %s", fid)
    response = requests.request("POST",
                                url=f"{url}/oauth2/token",
                                headers=headers,
                                params=params,
                                verify=settings.VERIFY_REQUEST_ENABLED
                                )
    if response.status_code != 200:
        logger.error(" IA RECOMMENDATION: Error generating token %s", response.text)
        error_response["status"] = "Error"
        return http_response.error(
            message="Error Get token",
            data=error_response
        )

    # Create threads
    access_token = response.json()["access_token"]
    url = GeneralSettings.get_value("HOST_IA_RECOMMENDATION_CORE")
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    body = {
        "thread_id": "",
        "metadata": {
            "user_id": user.email
        },
        "if_exists": "raise"
    }
    if version == "v2":
        body["metadata"].update({
            "agent_id": GeneralSettings.get_value("IA_AGENT_ID", "agent_id"),
            "consumer": "string"
            }) 
    logger.debug("IA RECOMMENDATION: get recomendation by finding: %s", fid)
    response = requests.request("POST",
                                url=f"{url}/core/api/{version}/threads",
                                headers=headers,
                                json=body,
                                verify=settings.VERIFY_REQUEST_ENABLED
                                )
    if response.status_code != 200:
        logger.error(" IA RECOMMENDATIONE: error getting IA RECOMMENDATION: %s", response.text)
        error_response["status"] = "Error"
        return http_response.error(
            message="Error Get threads",
            data=error_response
        )

    # Create runs
    thread_id = response.json()["thread_id"]
    url = GeneralSettings.get_value("HOST_IA_RECOMMENDATION_CORE")
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    body = {
        "agent_id": GeneralSettings.get_value("IA_AGENT_ID", "agent_id"),
        "thread_id": thread_id,
        "messages": str(fid),
        "metadata": {
            "user_id": user.email,
            "consumer": "string"
        }
    }

    if version == "v2":
        body["metadata"].update({
            "user_id": user.email,
            "consumer": "string"
            })

    logger.debug("IA RECOMMENDATION: get recomendation by finding: %s", fid)
    response = requests.request("POST",
                                url=f"{url}/core/api/{version}/runs",
                                headers=headers,
                                json=body,
                                verify=settings.VERIFY_REQUEST_ENABLED
                                )
    if response.status_code != 200:
        logger.error(" IA RECOMMENDATIONE: error getting IA RECOMMENDATION: %s", response.text)
        error_response["status"] = "Error"
        return http_response.error(message="Error runs", data=error_response)

    context = None
    if save:
        finding = get_object_or_404(Finding, id=fid)
        data = response.json()
        finding.ia_recommendation = {}
        finding.ia_recommendation["data"] = data
        finding.ia_recommendation["data"]["like_status"] = None
        finding.ia_recommendation["data"]["user"] = user.username
        finding.ia_recommendation["data"]["last_modified"] = str(timezone.now().date())
        finding.save(update_fields=["ia_recommendation"])
        context = finding_helper.parser_ia_recommendation(finding.ia_recommendation)
    return http_response.ok(message="OK", data=context) 

def order_finding_by_rules(findings, max_results=10):
    findings = sorted(findings, key=lambda f: (f.priority, f.sla_expiration_date), reverse=True)
    if len(findings) > max_results:
        findings = findings[:max_results]
    return (findings, ["Priority", "SLA Expiration Date"])


def context_process(findings: List[Finding], request):
    """
    Process findings and extract context with IA recommendations.
    Returns a list of findings with their processed context.
    """
    findings_with_context = []
    
    for finding in findings:
        # Extract Cliente from tags
        client = "vultrackerbatch"
        tags_list = [tag.name for tag in finding.tags.all()] if finding.tags.exists() else []
        # Extract user_email from reporter
        
        finding_data = {
            "client": client,
            "user_email": request.user.email,
            "id": finding.id,
            "tags": tags_list,
            "title": finding.title,
            "severity": finding.severity,
            "description": finding.description,
            "component_name": getattr(finding, 'component_name', None),
            "service": getattr(finding, 'service', None),
            "file_path": finding.file_path,
            "vuln_id_from_tool": getattr(finding, 'vuln_id_from_tool', None),
            "mitigation": getattr(finding, 'mitigation', None),
            "display_status": f"Active, {'Verified' if finding.verified else 'Not Verified'}",
            "vulnerability_ids": [{"vulnerability_id": vid} for vid in finding.get_vulnerability_ids().split(",") if vid]
        }
        
        # Extract related fields
        if finding.test and finding.test.engagement:
            engagement = finding.test.engagement
            finding_data["related_fields"] = {
                "test": {
                    "engagement": {
                        "name": engagement.name,
                        "source_code_management_uri": getattr(engagement, 'source_code_management_uri', ''),
                        "source_code_management_server": {
                            "name": engagement.source_code_management_server.name if engagement.source_code_management_server else ''
                        }
                    },
                    "branch_tag": getattr(finding.test, 'branch_tag', 'refs/heads/trunk')
                }
            }
        
        findings_with_context.append(finding_data)
    
    return json.dumps(findings_with_context)
