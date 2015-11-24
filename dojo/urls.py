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

urlpatterns = [
    #  django admin
    url(r'^admin/', include(admin.site.urls)),
    #  tastypie api
    url(r'^api/', include(v1_api.urls)),
    #  tastypie api
    url(r'^ajax/', include(ajax_api.urls)),
    # api doc urls
    url(r'api/v1/doc/',
        include('tastypie_swagger.urls', namespace='tastypie_swagger'),
        kwargs={
            "tastypie_api_module": "dojo.urls.v1_api",
            "namespace": "tastypie_swagger",
            "version": "1.0"}),
    # action history
    url(r'^history/(?P<cid>\d+)/(?P<oid>\d+)$', views.action_history,
        name='action_history'),
]

urlpatterns += dev_env_urls
urlpatterns += endpoint_urls
urlpatterns += eng_urls
urlpatterns += finding_urls
urlpatterns += home_urls
urlpatterns += metrics_urls
urlpatterns += prod_urls
urlpatterns += pt_urls
urlpatterns += reports_urls
urlpatterns += scan_urls
urlpatterns += search_urls
urlpatterns += test_type_urls
urlpatterns += test_urls
urlpatterns += user_urls


if settings.DEBUG:
    urlpatterns += patterns('django.views.static',
                            (r'media/(?P<path>.*)', 'serve', {
                                'document_root': settings.MEDIA_ROOT}))
