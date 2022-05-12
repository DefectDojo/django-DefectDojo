from django.conf.urls import url

from dojo.reports import views

urlpatterns = [
    #  reports
    url(r'^product/type/(?P<ptid>\d+)/report$',
        views.product_type_report, name='product_type_report'),
    url(r'^product/(?P<pid>\d+)/report$',
        views.product_report, name='product_report'),
    url(r'^product/(?P<pid>\d+)/endpoint/report$',
        views.product_endpoint_report, name='product_endpoint_report'),
    url(r'^engagement/(?P<eid>\d+)/report$', views.engagement_report,
        name='engagement_report'),
    url(r'^test/(?P<tid>\d+)/report$', views.test_report,
        name='test_report'),
    url(r'^endpoint/(?P<eid>\d+)/report$', views.endpoint_report,
        name='endpoint_report'),
    url(r'^endpoint/host/(?P<eid>\d+)/report$', views.endpoint_host_report,
        name='endpoint_host_report'),
    url(r'^product/report$',
        views.product_findings_report, name='product_findings_report'),
    url(r'^reports/cover$',
        views.report_cover_page, name='report_cover_page'),
    url(r'^reports/builder$',
        views.report_builder, name='report_builder'),
    url(r'^reports/findings$',
        views.report_findings, name='report_findings'),
    url(r'^reports/endpoints$',
        views.report_endpoints, name='report_endpoints'),
    url(r'^reports/custom$',
        views.custom_report, name='custom_report'),
    url(r'^reports/quick$',
        views.quick_report, name='quick_report'),
    url(r'^reports/csv_export$',
        views.csv_export, name='csv_export'),
    url(r'^reports/excel_export$',
        views.excel_export, name='excel_export'),
]
