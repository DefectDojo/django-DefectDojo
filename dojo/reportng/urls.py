from django.conf import settings
from django.urls import path

from . import views
from .builders import BUILDER_REGISTRY


# Register builder implementations
for builder_spec in settings.REPORTNG_BUILDERS:
    BUILDER_REGISTRY.register(builder_spec)

urlpatterns = [
    path("", views.ReportNGFilterView.as_view(), name="reportng_filter"),
    path("<int:pk>", views.ReportNGDetailView.as_view(), name="reportng_detail"),
    path("<int:pk>/delete", views.ReportNGDeleteView.as_view(), name="reportng_delete"),
    path(
        "<int:pk>/download",
        views.ReportNGDownloadView.as_view(),
        name="reportng_download",
    ),
    path(
        "builder/<str:builder_code>",
        views.ReportNGBuilderView.as_view(),
        name="reportng_builder",
    ),
    path(
        "builder/<str:builder_code>/draft/<int:draft_pk>",
        views.ReportNGBuilderView.as_view(),
        name="reportng_builder",
    ),
]
