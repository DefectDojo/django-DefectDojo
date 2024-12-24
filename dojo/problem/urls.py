from django.urls import re_path

from dojo.problem import views

urlpatterns = [
    # Listing operations
    re_path(
        r"^problems/all$",
        views.ListProblems.as_view(),
        name="all_problems",
    ),
    re_path(
        r"^problems/open$",
        views.ListOpenProblems.as_view(),
        name="open_problems",
    ),
    re_path(
        r"^problems/closed$",
        views.ListClosedProblems.as_view(),
        name="closed_problems",
    ),
    re_path(
        r"^problems/(?P<problem_id>\d+)/findings$",
        views.ProblemFindings.as_view(),
        name="problem_findings",
    )
]
