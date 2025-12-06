from django.urls import re_path

from dojo.risk_acceptance import views

urlpatterns = [
    re_path(r"^product/(?P<pid>\d+)/risk_acceptance/add$",
        views.add_risk_acceptance, name="add_risk_acceptance"),
    re_path(r"^product/(?P<pid>\d+)/risk_acceptance/add/(?P<fid>\d+)$",
        views.add_risk_acceptance, name="add_risk_acceptance"),
    re_path(r"^risk_acceptance/(?P<raid>\d+)$",
        views.view_risk_acceptance, name="view_risk_acceptance"),
    re_path(r"^risk_acceptance/(?P<raid>\d+)/edit$",
        views.edit_risk_acceptance, name="edit_risk_acceptance"),
    re_path(r"^risk_acceptance/(?P<raid>\d+)/expire$",
        views.expire_risk_acceptance, name="expire_risk_acceptance"),
    re_path(r"^risk_acceptance/(?P<raid>\d+)/reinstate$",
        views.reinstate_risk_acceptance, name="reinstate_risk_acceptance"),
    re_path(r"^risk_acceptance/(?P<raid>\d+)/delete$",
        views.delete_risk_acceptance, name="delete_risk_acceptance"),
    re_path(r"^risk_acceptance/(?P<raid>\d+)/download$",
        views.download_risk_acceptance, name="download_risk_acceptance"),
]
