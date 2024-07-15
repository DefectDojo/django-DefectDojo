from django.urls import re_path, path
from dojo.transfer_findings import views

urlpatterns = [
    path(
        "transfer_finding/delete/",
        views.TransferFindingDeleteView.as_view(),
        name='view_tranferFinding_delete'
    ),
]
