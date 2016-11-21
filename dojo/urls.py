from django.conf import settings
from django.conf.urls import patterns, include, url
from django.contrib import admin
from tastypie.api import Api

from dojo import views
from dojo.ajax import StubFindingResource as ajax_stub_finding_resource
from dojo.api import UserResource, ProductResource, EngagementResource, \
    TestResource, FindingResource, ScanSettingsResource, ScanResource, StubFindingResource
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
v1_api.register(ScanSettingsResource())
v1_api.register(ScanResource())
v1_api.register(StubFindingResource())
# v1_api.register(IPScanResource())

ajax_api = Api(api_name='v1_a')
ajax_api.register(ajax_stub_finding_resource())

ur = []
ur+= dev_env_urls
ur+= endpoint_urls
ur+= eng_urls
ur+= finding_urls
ur+= home_urls
ur+= metrics_urls
ur+= prod_urls
ur+= pt_urls
ur+= reports_urls
ur+= scan_urls
ur+= search_urls
ur+= test_type_urls
ur+= test_urls
ur+= user_urls
ur+= jira_urls

if not hasattr(settings, 'URL_PREFIX'):
    settings.URL_PREFIX = ''

urlpatterns = [
    #  django admin
    url(r'^%sadmin/' % settings.URL_PREFIX, include(admin.site.urls)),
    #  tastypie api
    url(r'^%sapi/' % settings.URL_PREFIX, include(v1_api.urls)),
    #  tastypie api
    url(r'^%sajax/' % settings.URL_PREFIX, include(ajax_api.urls)),
    # api doc urls
    url(r'%sapi/v1/doc/' % settings.URL_PREFIX,
        include('tastypie_swagger.urls', namespace='tastypie_swagger'),
        kwargs={
            "tastypie_api_module": "dojo.urls.v1_api",
            "namespace": "tastypie_swagger",
            "version": "1.0"}),
    # action history
    url(r'^%shistory/(?P<cid>\d+)/(?P<oid>\d+)$' % settings.URL_PREFIX, views.action_history,
        name='action_history'),
    url(r'^%s' % settings.URL_PREFIX, include(ur)),
]


if settings.DEBUG:
    urlpatterns += patterns('django.views.static',
                            (r'media/(?P<path>.*)', 'serve', {
                                'document_root': settings.MEDIA_ROOT}))
