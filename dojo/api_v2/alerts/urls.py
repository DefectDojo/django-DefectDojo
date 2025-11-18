from django.urls import path
from dojo.api_v2.alerts.views import AlertViewSet 

# Manager cache url

urlpatterns = [
    path("api/v2/alerts/", AlertViewSet.as_view({'get': 'list', 'post': 'create'}), name='alerts'),
]
