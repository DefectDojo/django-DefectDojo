import logging
import requests
import dojo.finding.helper as finding_helper
from django.utils import timezone
from django.shortcuts import get_object_or_404
from dojo.models import Finding
from dojo.models import GeneralSettings
from dojo.api_v2.ia_recommendation.serializers import IaRecommendationSerializer
from dojo.api_v2.utils import http_response
from django.conf import settings


logger = logging.getLogger(__name__)

def get_ia_recommendation(fid, user):
    error_response = {
        "status": "Ok",
        "ia_recommendations": (
                "At the moment, you can't generate a recommendation for this finding.\n"
                "Please try again later or with a different finding.🫣"
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

    access_token = response.json()["access_token"]
    url = GeneralSettings.get_value("HOST_IA_RECOMMENDATION_CORE")
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    body = {
        "thread_id": "",
        "metadata": {
            "user_id": "string"
        },
        "if_exists": "raise"
    }

    logger.debug("IA RECOMMENDATION: get recomendation by finding: %s", fid)
    response = requests.request("POST",
                                url=f"{url}/core/api/v1/threads",
                                headers=headers,
                                json=body,
                                verify=settings.VERIFY_REQUEST_ENABLED
                                )
    if response.status_code != 200:
        logger.error(" IA RECOMMENDATIONE: error getting IA RECOMMENDATION: %s", response.text)
        error_response["status"] = "Error"
        return http_response.error(message="Error get Thereads", data=error_response)
    
    thread_id = response.json()["thread_id"]
    url = GeneralSettings.get_value("HOST_IA_RECOMMENDATION_CORE")
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    body = {
        "agent_id": GeneralSettings.get_value("ia_agent_id", "marvin_ia_recommendation_agent"),
        "thread_id": thread_id,
        "messages": GeneralSettings.get_value("IA_MESSAGE", "Analyze the finding") + " " + fid,
        "metadata": {
            "user_id": "string"
        }
    }

    logger.debug("IA RECOMMENDATION: get recomendation by finding: %s", fid)
    response = requests.request("POST",
                                url=f"{url}/core/api/v1/runs",
                                headers=headers,
                                json=body,
                                verify=settings.VERIFY_REQUEST_ENABLED
                                )
    if response.status_code != 200:
        logger.error(" IA RECOMMENDATIONE: error getting IA RECOMMENDATION: %s", response.text)
        error_response["status"] = "Error"
        return http_response.error(message="Error runs", data=error_response)

    finding = get_object_or_404(Finding, id=fid)
    data = response.json()
    finding.ia_recommendation = {}
    finding.ia_recommendation["data"] = data
    finding.ia_recommendation["data"]["like_status"] = None
    finding.ia_recommendation["data"]["user"] = user.username
    finding.ia_recommendation["data"]["last_modified"] = str(timezone.now().date())
    finding.save()
    contex = finding_helper.parser_ia_recommendation(finding.ia_recommendation)
    return http_response.ok(message="OK", data=contex)