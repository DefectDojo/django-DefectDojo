from django.urls import re_path

from . import views

urlpatterns = [
    re_path(r"^webhook/(?P<secret>[\w-]+)$", views.webhook, name="web_hook_secret"),
    re_path(r"^webhook/", views.webhook, name="web_hook"),
    re_path(r"^jira/webhook/(?P<secret>[\w-]+)$", views.webhook, name="jira_web_hook_secret"),
    re_path(r"^jira/webhook/", views.webhook, name="jira_web_hook"),
    re_path(r"^jira/add", views.NewJiraView.as_view(), name="add_jira"),
    re_path(r"^jira/advanced", views.AdvancedJiraView.as_view(), name="add_jira_advanced"),
    re_path(r"^jira/(?P<jid>\d+)/edit$", views.EditJiraView.as_view(), name="edit_jira"),
    re_path(r"^jira/(?P<tid>\d+)/delete$", views.DeleteJiraView.as_view(), name="delete_jira"),
    re_path(r"^jira$", views.ListJiraView.as_view(), name="jira"),
]
