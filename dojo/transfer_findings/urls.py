from django.urls import re_path
from dojo.transfer_findings import views

urlpatterns = [
    re_path(
        r'^transfer_finding/(?P<transfer_finding_id>\d+)/delete$',
        views.ViewTransferFinding.as_view(),
        name='View_TranferFinding'
    ),
]