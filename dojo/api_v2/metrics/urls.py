from django.urls import path
from dojo.api_v2.metrics.views import MetricIARecommendationApiView

# Manager cache url

urlpatterns = [
    path("api/v2/metrics/ia_recommendation",
         MetricIARecommendationApiView.as_view(),
         name='metrics'),
]
