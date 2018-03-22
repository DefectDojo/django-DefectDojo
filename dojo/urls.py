from django.conf import settings
from django.conf.urls import include, url
from django.conf.urls.static import static
from django.contrib import admin
from tastypie.api import Api

from dojo import views
from dojo.api import UserResource, ProductResource, EngagementResource, \
    TestResource, FindingResource, ScanSettingsResource, ScanResource, \
    StubFindingResource, FindingTemplateResource, ImportScanResource, \
    ReImportScanResource, JiraResource, JIRA_ConfResource, EndpointResource, \
    JIRA_IssueResource, ToolProductSettingsResource, Tool_ConfigurationResource, \
    Tool_TypeResource, LanguagesResource, LanguageTypeResource, App_AnalysisResource, \
    BuildDetails
from dojo.utils import get_system_setting
from dojo.development_environment.urls import urlpatterns as dev_env_urls
from dojo.endpoint.urls import urlpatterns as endpoint_urls
from dojo.engagement.urls import urlpatterns as eng_urls
from dojo.finding.urls import urlpatterns as finding_urls
from dojo.home.urls import urlpatterns as home_urls
from dojo.metrics.urls import urlpatterns as metrics_urls
from dojo.product.urls import urlpatterns as prod_urls
from dojo.product_type.urls import urlpatterns as pt_urls
from dojo.reports.urls import urlpatterns as reports_urls
from dojo.scan.urls import urlpatterns as scan_urls
from dojo.search.urls import urlpatterns as search_urls
from dojo.test.urls import urlpatterns as test_urls
from dojo.test_type.urls import urlpatterns as test_type_urls
from dojo.user.urls import urlpatterns as user_urls
from dojo.jira_link.urls import urlpatterns as jira_urls
from dojo.tool_type.urls import urlpatterns as tool_type_urls
from dojo.tool_config.urls import urlpatterns as tool_config_urls
from dojo.tool_product.urls import urlpatterns as tool_product_urls
from dojo.cred.urls import urlpatterns as cred_urls
from dojo.system_settings.urls import urlpatterns as system_settings_urls
from dojo.notifications.urls import urlpatterns as notifications_urls
from dojo.object.urls import urlpatterns as object_urls
import sys

admin.autodiscover()

"""
        Bind multiple resources together to form a coherent API.
"""
v1_api = Api(api_name='v1', )
v1_api.register(UserResource())
v1_api.register(ProductResource())
v1_api.register(EngagementResource())
v1_api.register(TestResource())
v1_api.register(FindingResource())
v1_api.register(FindingTemplateResource())
v1_api.register(ScanSettingsResource())
v1_api.register(ScanResource())
v1_api.register(StubFindingResource())
v1_api.register(ImportScanResource())
v1_api.register(ReImportScanResource())
v1_api.register(EndpointResource())
v1_api.register(JiraResource())
v1_api.register(JIRA_ConfResource())
v1_api.register(JIRA_IssueResource())
v1_api.register(ToolProductSettingsResource())
v1_api.register(Tool_ConfigurationResource())
v1_api.register(Tool_TypeResource())
v1_api.register(LanguagesResource())
v1_api.register(LanguageTypeResource())
v1_api.register(App_AnalysisResource())
v1_api.register(BuildDetails())
# v1_api.register(IPScanResource())


ur = []
ur += dev_env_urls
ur += endpoint_urls
ur += eng_urls
ur += finding_urls
ur += home_urls
ur += metrics_urls
ur += prod_urls
ur += pt_urls
ur += reports_urls
ur += scan_urls
ur += search_urls
ur += test_type_urls
ur += test_urls
ur += user_urls
ur += jira_urls
ur += tool_type_urls
ur += tool_config_urls
ur += tool_product_urls
ur += cred_urls
ur += system_settings_urls
ur += notifications_urls
ur += object_urls

from tastypie_swagger.views import SwaggerView, ResourcesView, SchemaView

swagger_urls = [
    url(r'^$', SwaggerView.as_view(), name='index'),
    url(r'^resources/$', ResourcesView.as_view(), name='resources'),
    url(r'^schema/(?P<resource>\S+)$', SchemaView.as_view()),
    url(r'^schema/$', SchemaView.as_view(), name='schema'),
]



urlpatterns = [
    #  django admin
    url(r'^%sadmin/' % get_system_setting('url_prefix'), include(admin.site.urls)),
    #  tastypie api
    url(r'^%sapi/' % get_system_setting('url_prefix'), include(v1_api.urls)),
    # api doc urls
    url(r'%sapi/v1/doc/' % get_system_setting('url_prefix'),
        include(swagger_urls, namespace='tastypie_swagger'),
        kwargs={
            "tastypie_api_module": "dojo.urls.v1_api",
            "namespace": "tastypie_swagger",
            "version": "1.0"}),
    # action history
    url(r'^%shistory/(?P<cid>\d+)/(?P<oid>\d+)$' % get_system_setting('url_prefix'), views.action_history,
        name='action_history'),
    url(r'^%s' % get_system_setting('url_prefix'), include(ur)),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
