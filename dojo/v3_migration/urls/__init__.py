from django.urls import include, re_path

from dojo.urls import common_urlpatterns
from dojo.utils import get_system_setting
from dojo.v3_migration.urls.assets import urlpatterns as assets_urlpatterns
from dojo.v3_migration.urls.metrics import urlpatterns as metrics_urlpatterns
from dojo.v3_migration.urls.organizations import urlpatterns as organizations_urlpatterns
from dojo.v3_migration.urls.reports import urlpatterns as reports_urlpatterns

v3_urls = organizations_urlpatterns + assets_urlpatterns + reports_urlpatterns + metrics_urlpatterns

urlpatterns = [*common_urlpatterns, re_path(r"^{}".format(get_system_setting("url_prefix")), include(v3_urls))]
