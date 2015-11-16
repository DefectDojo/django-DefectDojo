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
    url(r'^product/report$',
        views.product_findings_report, name='product_findings_report'),
]