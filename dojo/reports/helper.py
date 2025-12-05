import re
import logging
from dojo.authorization.roles_permissions import Permissions
from django.shortcuts import get_object_or_404
from django.conf import settings
from dojo.finding.views import BaseListFindings
from dojo.authorization.authorization import user_has_permission_or_403
from dojo.models import Product, Engagement, Test
from dojo.reports.custom_request import CustomRequest
from dojo.celery import app
from dojo.models import GeneralSettings
from dojo.reports.report_manager import CSVReportManager, ExcelReportManager, HtmlReportManager
from django.http import Http404, QueryDict

logger = logging.getLogger(__name__)


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

    views = [
        "all",
        "open",
        "inactive",
        "verified",
        "closed",
        "accepted",
        "out_of_scope",
        "false_positive",
        "inactive",
    ]
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
        filter_name=filter_name, product_id=pid, engagement_id=eid, test_id=tid
    )
    findings = list_findings.get_fully_filtered_findings(request).qs

    return findings, obj, url


def get_name_key(user, product):
    """
    Generate a unique key for the report based on the user's name and current time.
    """
    url = GeneralSettings.get_value("URL_FILE_BUKECT_REPORT_FINDINGS", "")
    key = f"{url}/{product}_{user.username}.csv"
    return key


@app.task()
def async_generate_report(request_data: dict):
    logger.debug(f"REPORT FINDING: async_generate_report {request_data}")
    request = CustomRequest(**request_data)
    findings, obj, _url = get_findings(request)
    if findings.count() == 0:
        raise Exception(500, "No findings found for the report.")
    
    format_type = request_data.get("format")
    
    if format_type == "csv":
        report_class = CSVReportManager(findings, request)
    elif format_type == "excel":
        report_class = ExcelReportManager(findings, request)
    elif format_type == "html":
        report_class = HtmlReportManager(findings, request, obj)
    else:
        logger.error(f"REPORT FINDING: Unsupported format: {format_type}")
        raise Exception(400, f"Unsupported report format: {format_type}")
    
    report_class.generate_report()


def get_excludes():
    return GeneralSettings.get_value(
        "EXCLUDE_FIELDS_REPORT",
        [
            "SEVERITIES",
            "age",
            "github_issue",
            "jira_issue",
            "objects",
            "risk_acceptance",
            "test__engagement__product__authorized_group",
            "test__engagement__product__member",
            "test__engagement__product__prod_type__authorized_group",
            "test__engagement__product__prod_type__member",
            "unsaved_endpoints",
            "unsaved_vulnerability_ids",
            "unsaved_files",
            "unsaved_request",
            "unsaved_response",
            "unsaved_tags",
            "vulnerability_ids",
            "cve",
            "transferfindingfinding",
            "transfer_finding",
        ],
    )
