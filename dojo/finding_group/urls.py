from django.urls import re_path

from dojo.finding_group import views, views_dynamic

urlpatterns = [
    # finding group
    re_path(r"^finding_group/(?P<fgid>\d+)$", views.view_finding_group, name="view_finding_group"),
    re_path(r"^finding_group/(?P<fgid>\d+)/delete$", views.delete_finding_group, name="delete_finding_group"),
    re_path(r"^finding_group/(?P<fgid>\d+)/jira/push$", views.push_to_jira, name="finding_group_push_to_jira"),
    re_path(r"^finding_group/(?P<fgid>\d+)/jira/unlink$", views.unlink_jira, name="finding_group_unlink_jira"),

    # static finding group list views
    re_path(r"^finding_group/all$", views.ListFindingGroups.as_view(), name="all_finding_groups"),
    re_path(r"^finding_group/open$", views.ListOpenFindingGroups.as_view(), name="open_finding_groups"),
    re_path(r"^finding_group/closed$", views.ListClosedFindingGroups.as_view(), name="closed_finding_groups"),

    # dynamic finding group list views
    re_path(r"^dynamic_finding_group/all$", views_dynamic.ListDynamicFindingGroups.as_view(), name="all_dynamic_finding_groups"),
    re_path(r"^dynamic_finding_group/open$", views_dynamic.ListOpenDynamicFindingGroups.as_view(), name="open_dynamic_finding_groups"),
    re_path(r"^dynamic_finding_group/closed$", views_dynamic.ListClosedDynamicFindingGroups.as_view(), name="closed_dynamic_finding_groups"),
    re_path(r"^dynamic_finding_group/(?P<finding_group_id>[^/]+)/findings$", views_dynamic.DynamicFindingGroupsFindings.as_view(), name="dynamic_finding_group_findings"),
]
