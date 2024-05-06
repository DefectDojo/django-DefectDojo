from django.urls import re_path

from dojo.finding_group import views

urlpatterns = [
    # finding group
    re_path(r'^finding_group/(?P<fgid>\d+)$', views.view_finding_group, name='view_finding_group'),
    re_path(r'^finding_group/(?P<fgid>\d+)/delete$', views.delete_finding_group, name='delete_finding_group'),
    re_path(r'^finding_group/(?P<fgid>\d+)/jira/push$', views.push_to_jira, name='finding_group_push_to_jira'),
    re_path(r'^finding_group/(?P<fgid>\d+)/jira/unlink$', views.unlink_jira, name='finding_group_unlink_jira'),
]
