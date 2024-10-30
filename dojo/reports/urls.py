from django.urls import re_path

from dojo.reports import views

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
    re_path(r"^endpoint/(?P<eid>\d+)/report$", views.endpoint_report,
        name="endpoint_report"),
    re_path(r"^endpoint/host/(?P<eid>\d+)/report$", views.endpoint_host_report,
        name="endpoint_host_report"),
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
]
