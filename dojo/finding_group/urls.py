from django.conf.urls import url

from dojo.finding_group import views

urlpatterns = [
    # finding group
    url(r'^finding_group/(?P<fgid>\d+)$', views.view_finding_group, name='view_finding_group'),
    url(r'^finding_group/(?P<fgid>\d+)/edit$', views.edit_finding_group, name='edit_finding_group'),
    url(r'^finding_group/(?P<fgid>\d+)/delete$', views.delete_finding_group, name='delete_finding_group'),

    url(r'^finding_group/(?P<fgid>\d+)/jira/push$', views.push_to_jira, name='finding_group_push_to_jira'),
    url(r'^finding_group/(?P<fgid>\d+)/jira/unlink$', views.unlink_jira, name='finding_group_unlink_jira'),
]
