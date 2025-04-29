from django.urls import path
from dojo.api_v2.manager_cache.views import ManagerCacheApiView

# Manager cache url

urlpatterns = [
    path("api/v2/manager-cache/", ManagerCacheApiView.as_view(), name='manager-cache'),
]
