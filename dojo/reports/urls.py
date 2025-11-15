from django.conf import settings
from django.urls import re_path

from dojo.reports import views
from dojo.utils import redirect_view

# TODO: remove the else: branch once v3 migration is complete
if settings.ENABLE_V3_ORGANIZATION_ASSET_RELABEL:
    urlpatterns = [
        re_path(
            r"^organization/(?P<ptid>\d+)/report$",
            views.product_type_report,
            name="product_type_report",
        ),
        re_path(
            r"^asset/(?P<pid>\d+)/report$",
            views.product_report,
            name="product_report",
        ),
        re_path(
            r"^asset/(?P<pid>\d+)/endpoint/report$",
            views.product_endpoint_report,
            name="product_endpoint_report",
        ),
        re_path(
            r"^engagement/(?P<eid>\d+)/report$",
            views.engagement_report,
            name="engagement_report",
        ),
        re_path(
            r"^test/(?P<tid>\d+)/report$",
            views.test_report,
            name="test_report",
        ),
        re_path(
            r"^asset/report$",
            views.product_findings_report,
            name="product_findings_report",
        ),
        re_path(
            r"^reports/cover$",
            views.report_cover_page,
            name="report_cover_page",
        ),
        re_path(
            r"^reports/builder$",
            views.ReportBuilder.as_view(),
            name="report_builder",
        ),
        re_path(
            r"^reports/findings$",
            views.report_findings,
            name="report_findings",
        ),
        re_path(
            r"^reports/endpoints$",
            views.report_endpoints,
            name="report_endpoints",
        ),
        re_path(
            r"^reports/custom$",
            views.CustomReport.as_view(),
            name="custom_report",
        ),
        re_path(
            r"^reports/quick$",
            views.QuickReportView.as_view(),
            name="quick_report",
        ),
        re_path(
            r"^reports/csv_export$",
            views.CSVExportView.as_view(),
            name="csv_export",
        ),
        re_path(
            r"^reports/excel_export$",
            views.ExcelExportView.as_view(),
            name="excel_export",
        ),
        # TODO: Backwards compatibility; remove after v3 migration is complete
        re_path(r"^product/type/(?P<ptid>\d+)/report$", redirect_view("product_type_report")),
        re_path(r"^product/(?P<pid>\d+)/report$", redirect_view("product_report")),
        re_path(r"^product/(?P<pid>\d+)/endpoint/report$", redirect_view("product_endpoint_report")),
        re_path(r"^product/report$", redirect_view("product_findings_report")),
    ]
else:
    urlpatterns = [
        #  reports
        re_path(r"^product/type/(?P<ptid>\d+)/report$",
            views.product_type_report, name="product_type_report"),
        re_path(r"^product/(?P<pid>\d+)/report$",
            views.product_report, name="product_report"),
        re_path(r"^product/(?P<pid>\d+)/endpoint/report$",
            views.product_endpoint_report, name="product_endpoint_report"),
        re_path(r"^engagement/(?P<eid>\d+)/report$", views.engagement_report,
            name="engagement_report"),
        re_path(r"^test/(?P<tid>\d+)/report$", views.test_report,
            name="test_report"),
        re_path(r"^product/report$",
            views.product_findings_report, name="product_findings_report"),
        re_path(r"^reports/cover$",
            views.report_cover_page, name="report_cover_page"),
        re_path(r"^reports/builder$",
            views.ReportBuilder.as_view(), name="report_builder"),
        re_path(r"^reports/findings$",
            views.report_findings, name="report_findings"),
        re_path(r"^reports/endpoints$",
            views.report_endpoints, name="report_endpoints"),
        re_path(r"^reports/custom$",
            views.CustomReport.as_view(), name="custom_report"),
        re_path(r"^reports/quick$",
            views.QuickReportView.as_view(), name="quick_report"),
        re_path(r"^reports/csv_export$",
            views.CSVExportView.as_view(), name="csv_export"),
        re_path(r"^reports/excel_export$",
            views.ExcelExportView.as_view(), name="excel_export"),
        # Forward compatibility
        re_path(r"^organization/(?P<ptid>\d+)/report$", redirect_view("product_type_report")),
        re_path(r"^asset/(?P<pid>\d+)/report$", redirect_view("product_report")),
        re_path(r"^asset/(?P<pid>\d+)/endpoint/report$", redirect_view("product_endpoint_report")),
        re_path(r"^asset/report$", redirect_view("product_findings_report")),
    ]
