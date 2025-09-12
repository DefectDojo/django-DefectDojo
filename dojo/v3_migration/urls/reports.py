from django.urls import re_path

from dojo.reports import views
from dojo.reports.urls import common_urlpatterns
from dojo.v3_migration import redirect_view

v3_urlpatterns = [
    #  reports
    re_path(r"^organization/(?P<ptid>\d+)/report$",
          views.product_type_report, name="product_type_report"),
    re_path(r"^asset/(?P<pid>\d+)/report$",
          views.product_report, name="product_report"),
    re_path(r"^asset/(?P<pid>\d+)/endpoint/report$",
          views.product_endpoint_report, name="product_endpoint_report"),
    re_path(r"^asset/report$",
          views.product_findings_report, name="product_findings_report"),
]

v2_backward_urlpatterns = [
    #  reports
    re_path(r"^product/type/(?P<ptid>\d+)/report$", redirect_view("product_type_report")),
    re_path(r"^product/(?P<pid>\d+)/report$", redirect_view("product_report")),
    re_path(r"^product/(?P<pid>\d+)/endpoint/report$", redirect_view("product_endpoint_report")),
    re_path(r"^product/report$", redirect_view("product_findings_report")),
]

urlpatterns = common_urlpatterns + v3_urlpatterns + v2_backward_urlpatterns
