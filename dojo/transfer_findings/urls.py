from django.urls import re_path, path
from dojo.transfer_findings import views

urlpatterns = [
    path(
        "transfer_finding/delete/",
        views.TransferFindingDeleteView.as_view(),
        name='view_tranferFinding_delete'
    ),
    path("transfer_finding/<int:pk>/edit/",
         views.TransferFindingUpdateView.as_view(),
         name="transferfinding_update_form")
]
