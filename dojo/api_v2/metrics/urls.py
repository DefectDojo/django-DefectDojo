from django.urls import path
from dojo.api_v2.metrics.views import (
    MetricIARecommendationApiView,
    MetricsDevicesWithoutFindingsApiView,
)

# Manager cache url

urlpatterns = [
    path("api/v2/metrics/ia_recommendation",
         MetricIARecommendationApiView.as_view(),
         name='metrics_ia_recommendation'),
    path("api/v2/metrics/devices_without_findings",
         MetricsDevicesWithoutFindingsApiView.as_view(),
         name="metrics_devices_without_findings"),
]
