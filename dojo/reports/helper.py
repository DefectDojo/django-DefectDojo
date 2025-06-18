import re
import logging
import boto3
import botocore.exceptions
from dojo.api_v2.api_error import ApiError
from time import sleep
from dojo.authorization.roles_permissions import Permissions
from django.shortcuts import get_object_or_404, render
from dojo.finding.views import BaseListFindings
from dojo.authorization.authorization import user_has_permission_or_403
from dojo.models import Product, Engagement, Test
from django.utils import timezone
from dojo.reports.custom_request import CustomRequest
from dojo.celery import app
from dojo.models import Dojo_User
from dojo.models import GeneralSettings
from dojo.reports.report_manager import CSVReportManager
from django.http import Http404, HttpRequest, HttpResponse, QueryDict
from dojo.notifications.helper import create_notification
logger = logging.getLogger(__name__)

BUCKET = 'mybuket-rene'
KEY = 'reportes/reporte.csv'
CHUNKSIZE = 1


def upload_s3(session_s3, buffer, bucket, key, retries=3, delay=10):
    for attempt in range(retries):
        try:
            response = session_s3.put_object(Bucket=bucket, Key=key, Body=buffer.getvalue())
            logger.info(f"REPORT FINDING: Upload successful: {response}")
            if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
                return response
            else:
                logger.error(f"REPORT FINDING: Upload failed with status code: {response['ResponseMetadata']['HTTPStatusCode']}")
                raise Exception(response["ResponseMetadata"]["HTTPStatusCode"], "Failed to upload to S3")
        except Exception as e:
            logger.error(f"REPORT FINDING: Attempt {attempt + 1} failed with error: {e}")
            sleep(delay)
    raise Exception("Failed to upload to S3 after multiple attempts due to expired token.")


def get_url_presigned(session,
                      key,
                      buket,
                      expires_in=3600):
    url = session.generate_presigned_url(
        'get_object',
        Params={'Bucket': buket, 'Key': key},
        ExpiresIn=expires_in
    )
    logger.debug(f"REPORT FINDING: {url}")
    return url


def get_list_index(full_list, index):
    try:
        element = full_list[index]
    except Exception:
        element = None
    return element


def get_findings(request):
    url = request.META.get("QUERY_STRING")
    if not url:
        msg = "Please use the report button when viewing findings"
        raise Http404(msg)
    url = url.removeprefix("url=")

    views = ["all", "open", "inactive", "verified",
             "closed", "accepted", "out_of_scope",
             "false_positive", "inactive"]
    obj_name = obj_id = view = query = None
    path_items = list(filter(None, re.split(r"/|\?", url)))

    try:
        finding_index = path_items.index("finding")
    except ValueError:
        finding_index = -1
    # There is a engagement or product here
    if finding_index > 0:
        # path_items ['product', '1', 'finding', 'closed', 'test__engagement__product=1']
        obj_name = get_list_index(path_items, 0)
        obj_id = get_list_index(path_items, 1)
        view = get_list_index(path_items, 3)
        query = get_list_index(path_items, 4)
        # Try to catch a mix up
        query = query if view in views else view
    # This is findings only. Accomodate view and query
    elif finding_index == 0:
        # path_items ['finding', 'closed', 'title=blah']
        obj_name = get_list_index(path_items, 0)
        view = get_list_index(path_items, 1)
        query = get_list_index(path_items, 2)
        # Try to catch a mix up
        query = query if view in views else view
    # This is a test or engagement only
    elif finding_index == -1:
        # path_items ['test', '1', 'test__engagement__product=1']
        obj_name = get_list_index(path_items, 0)
        obj_id = get_list_index(path_items, 1)
        query = get_list_index(path_items, 2)

    filter_name = None
    if view:
        if view == "open":
            filter_name = "Open"
        elif view == "inactive":
            filter_name = "Inactive"
        elif view == "verified":
            filter_name = "Verified"
        elif view == "closed":
            filter_name = "Closed"
        elif view == "accepted":
            filter_name = "Accepted"
        elif view == "out_of_scope":
            filter_name = "Out of Scope"
        elif view == "false_positive":
            filter_name = "False Positive"

    obj = pid = eid = tid = None
    if obj_id:
        if "product" in obj_name:
            pid = obj_id
            obj = get_object_or_404(Product, id=pid)
            user_has_permission_or_403(request.user, obj, Permissions.Product_View)
        elif "engagement" in obj_name:
            eid = obj_id
            obj = get_object_or_404(Engagement, id=eid)
            user_has_permission_or_403(request.user, obj, Permissions.Engagement_View)
        elif "test" in obj_name:
            tid = obj_id
            obj = get_object_or_404(Test, id=tid)
            user_has_permission_or_403(request.user, obj, Permissions.Test_View)

    request.GET = QueryDict(query)
    list_findings = BaseListFindings(
        filter_name=filter_name,
        product_id=pid,
        engagement_id=eid,
        test_id=tid)
    findings = list_findings.get_fully_filtered_findings(request).qs

    return findings, obj


def get_name_key(user, product):
    """
    Generate a unique key for the report based on the user's name and current time.
    """
    url = GeneralSettings.get_value("URL_FILE_BOKECT_REPORT_FINDINGS", "")
    key = f"{url}/{product}_{user.username}.csv"
    return key 


@app.task
def async_generate_report(request_data: dict):
    logger.debug(f"REPORT FINDING: async_generate_report {request_data}")
    request = CustomRequest(**request_data)
    findings, _obj = get_findings(request)
    if findings.count() == 0:
        raise Exception(500, "No findings found for the report.")
    csv_report_manager = CSVReportManager(
       findings, request
    )
    report_csv = csv_report_manager.generate_report()
    bucket = GeneralSettings.get_value("BUCKET_NAME_REPORT", "")
    
    try:
        session_s3 = boto3.Session().client('s3')
        response = upload_s3(
            session_s3,
            report_csv,
            bucket,
            KEY,
        )
        if response["ResponseMetadata"]["HTTPStatusCode"] == 200:
            url = get_url_presigned(
                session_s3,
                KEY,
                bucket
            )
            logger.debug(f"REPORT FINDING: URL {url}")
            create_notification(
                subject=f"Reporte Finding is ready🔔")
            return response
    except botocore.exceptions.ClientError as e:
        logger.error(f"Failed to upload report to S3: {e}")
        raise


def get_excludes():
    return [
        "SEVERITIES", "age", "github_issue", "jira_issue",
        "objects", "risk_acceptance",
        "test__engagement__product__authorized_group",
        "test__engagement__product__member",
        "test__engagement__product__prod_type__authorized_group",
        "test__engagement__product__prod_type__member",
        "unsaved_endpoints", "unsaved_vulnerability_ids",
        "unsaved_files", "unsaved_request", "unsaved_response",
        "unsaved_tags", "vulnerability_ids", "cve",
        "transferfindingfinding", "transfer_finding"]


def get_foreign_keys():
    return [
        "defect_review_requested_by",
        "duplicate_finding", "finding_group",
        "last_reviewed_by", "mitigated_by",
        "reporter", "review_requested_by",
        "sonarqube_issue", "test"]


def get_attributes():
    return ["sla_age", "sla_deadline", "sla_days_remaining"]
