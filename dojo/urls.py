from django.conf import settings
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.contrib.auth.views import login
from tastypie.api import Api
from dojo.api import UserResource, ProductResource, EngagementResource, \
    TestResource, FindingResource, ScanSettingsResource, ScanResource
from dojo import views
admin.autodiscover()


"""
        Bind multiple resources together to form a coherent API.
"""
v1_api = Api(api_name='v1')
v1_api.register(UserResource())
v1_api.register(ProductResource())
v1_api.register(EngagementResource())
v1_api.register(TestResource())
v1_api.register(FindingResource())
v1_api.register(ScanSettingsResource())
v1_api.register(ScanResource())
# v1_api.register(IPScanResource())


urlpatterns = [
    #  django admin
    url(r'^admin/', include(admin.site.urls)),

    #  dojo home pages
    url(r'^$', views.home, name='home'),
    url(r'^dashboard$', views.dashboard, name='dashboard'),

    #  tastypie api
    url(r'^api/', include(v1_api.urls)),
    url(r'^api/key$', views.api_key, name='api_key'),

    #  user specific
    url(r'^login$', login,
        {'template_name': 'dojo/login.html'}, name='login'),
    url(r'^logout$', views.logout_view, name='logout'),
    url(r'^alerts$', views.alerts, name='alerts'),
    url(r'^profile$', views.view_profile, name='view_profile'),
    url(r'^change_password$', views.change_password,
        name='change_password'),
    url(r'^user$', views.user, name='users'),
    url(r'^user/add$', views.add_user, name='add_user'),
    url(r'^user/(?P<uid>\d+)/edit$', views.edit_user,
        name='edit_user'),
    url(r'^user/(?P<uid>\d+)/delete', views.delete_user,
        name='delete_user'),

    #  search
    url(r'^simple_search$', views.simple_search,
        name='simple_search'),

    # calendar
    url(r'^calendar$', views.calendar, name='calendar'),
    # url(r'^date_update/(?P<last_month>\d+)$', views.calc',
    #     name='date_update'),

    #  product
    url(r'^product$', views.product, name='product'),
    url(r'^product/(?P<pid>\d+)$', views.view_product,
        name='view_product'),
    url(r'^product/(?P<pid>\d+)/edit$', views.edit_product,
        name='edit_product'),
    url(r'^product/(?P<pid>\d+)/delete$', views.delete_product,
        name='delete_product'),
    url(r'^product/add', views.new_product, name='new_product'),
    url(r'^product/(?P<pid>\d+)/findings$',
        views.all_product_findings, name='view_product_findings'),
    url(r'^product/(?P<pid>\d+)/new_engagement$', views.new_eng_for_app,
        name='new_eng_for_prod'),

    #  product type
    url(r'^product/type$', views.product_type, name='product_type'),
    url(r'^product/type/(?P<ptid>\d+)/edit$',
        views.edit_product_type, name='edit_product_type'),
    url(r'^product/type/add$', views.add_product_type,
        name='add_product_type'),
    url(r'^product/type/(?P<ptid>\d+)/add_product',
        views.add_product_to_product_type,
        name='add_product_to_product_type'),

    #  engagements
    url(r'^engagement$', views.engagement, name='engagement'),
    url(r'^engagement/new$', views.new_engagement, name='new_eng'),
    url(r'^engagement/(?P<eid>\d+)$', views.view_engagement,
        name='view_engagement'),
    url(r'^engagement/(?P<eid>\d+)/ics$', views.engagement_ics,
        name='engagement_ics'),
    url(r'^engagement/(?P<eid>\d+)/edit$', views.edit_engagement,
        name='edit_engagement'),
    url(r'^engagement/(?P<eid>\d+)/delete$', views.delete_engagement,
        name='delete_engagement'),
    url(r'^engagement/(?P<eid>\d+)/add_tests$', views.add_tests,
        name='add_tests'),
    url(r'^engagement/(?P<eid>\d+)/import_scan_results$',
        views.import_scan_results, name='import_scan_results'),
    url(r'^engagement/(?P<eid>\d+)/close$', views.close_eng,
        name='close_engagement'),
    url(r'^engagement/(?P<eid>\d+)/reopen$', views.reopen_eng,
        name='reopen_engagement'),
    url(r'^engagement/(?P<eid>\d+)/complete_checklist$',
        views.complete_checklist, name='complete_checklist'),
    url(r'^engagement/(?P<eid>\d+)/upload_risk_acceptance$',
        views.upload_risk, name='upload_risk_acceptance$'),
    url(r'^engagement/(?P<eid>\d+)/risk_approval/(?P<raid>\d+)$',
        views.view_risk, name='view_risk'),
    url(r'^engagement/(?P<eid>\d+)/risk_approval/(?P<raid>\d+)/delete$',
        views.delete_risk, name='delete_risk'),
    url(r'^engagement/(?P<eid>\d+)/risk_approval/(?P<raid>\d+)/download$',
        views.download_risk, name='download_risk'),
    url(r'^engagement/(?P<eid>\d+)/threatmodel$', views.view_threatmodel,
        name='view_threatmodel'),
    url(r'^engagement/(?P<eid>\d+)/threatmodel/upload$',
        views.upload_threatmodel, name='upload_threatmodel'),


    #  findings
    url(r'^finding$', views.open_findings,
        name='findings'),
    url(r'^finding/open$', views.open_findings,
        name='open_findings'),
    url(r'^finding/closed$', views.closed_findings,
        name='closed_findings'),
    url(r'^finding/accepted', views.accepted_findings,
        name='accepted_findings'),
    url(r'^finding/(?P<fid>\d+)$', views.view_finding,
        name='view_finding'),
    url(r'^finding/(?P<fid>\d+)/edit$',
        views.edit_finding, name='edit_finding'),
    url(r'^finding/(?P<fid>\d+)/touch',
        views.touch_finding, name='touch_finding'),
    url(r'^finding/(?P<fid>\d+)/delete$',
        views.delete_finding, name='delete_finding'),
    url(r'^finding/(?P<fid>\d+)/mktemplate$', views.mktemplate,
        name='mktemplate'),
    url(r'^finding/(?P<fid>\d+)/close$', views.close_finding,
        name='close_finding'),
    url(r'^finding/(?P<tid>\d+)/note/(?P<nid>\d+)/delete$',
        views.delete_finding_note, name='delete_finding_note'),

    #  metrics
    url(r'^metrics$', views.metrics, {'mtype': 'All'},
        name='metrics'),
    url(r'^metrics/all$', views.metrics, {'mtype': 'All'},
        name='metrics_all'),
    url(r'^metrics/product/type$', views.metrics, {'mtype': 'All'},
        name='metrics_product_type'),
    url(r'^metrics/simple$', views.simple_metrics,
        name='simple_metrics'),
    url(r'^metrics/product/type/(?P<mtype>\d+)$',
        views.metrics, name='product_type_metrics'),
    url(r'^metrics/product/type/counts$',
        views.product_type_counts, name='product_type_counts'),
    url(r'^metrics/engineer$', views.engineer_metrics,
        name='engineer_metrics'),
    url(r'^metrics/research$', views.research_metrics,
        name='research_metrics'),
    url(r'^metrics/engineer/(?P<eid>\d+)$', views.view_engineer,
        name='view_engineer'),

    # test types
    url(r'^test_type$', views.test_type, name='test_type'),
    url(r'^test_type/add$', views.add_test_type,
        name='add_test_type'),
    url(r'^test_type/(?P<ptid>\d+)/edit$',
        views.edit_test_type, name='edit_test_type'),

    #dev envs
    url(r'^dev_env$', views.dev_env, name='dev_env'),
    url(r'^dev_env/add$', views.add_dev_env,
        name='add_dev_env'),
    url(r'^dev_env/(?P<deid>\d+)/edit$',
        views.edit_dev_env, name='edit_dev_env'),

    #  tests
    url(r'^test/(?P<tid>\d+)$', views.view_test,
        name='view_test'),
    url(r'^test/(?P<tid>\d+)/ics$', views.test_ics,
        name='test_ics'),
    url(r'^test/(?P<tid>\d+)/edit$', views.edit_test,
        name='edit_test'),
    url(r'^test/(?P<tid>\d+)/delete$', views.delete_test,
        name='delete_test'),
    url(r'^test/(?P<tid>\d+)/add_findings$', views.add_findings,
        name='add_findings'),
    url(r'^test/(?P<tid>\d+)/add_findings/(?P<fid>\d+)$',
        views.add_temp_finding, name='add_temp_finding'),
    url(r'^test/(?P<tid>\d+)/note/(?P<nid>\d+)/delete$',
        views.delete_test_note, name='delete_test_note'),
    url(r'^test/(?P<tid>\d+)/search$', views.search, name='search'),
    url(r'^test/(?P<tid>\d+)/re_import_scan_results', views.re_import_scan_results, name='re_import_scan_results'),

    # scans and scan settings
    url(r'^scan/(?P<sid>\d+)$', views.view_scan,
        name='view_scan'),
    url(r'^product/(?P<pid>\d+)/scan/add$', views.gmap, name='gmap'),
    url(r'^product/(?P<pid>\d+)/scan/(?P<sid>\d+)/settings$',
        views.view_scan_settings, name='view_scan_settings'),
    url(r'^product/(?P<pid>\d+)/scan/(?P<sid>\d+)/edit$',
        views.edit_scan_settings, name='edit_scan_settings'),

    #  reports
    url(r'^product/type/(?P<ptid>\d+)/report$',
        views.product_type_report, name='product_type_report'),
    url(r'^product/(?P<pid>\d+)/report$',
        views.product_report, name='product_report'),
    url(r'^product/(?P<pid>\d+)/endpoint/report$',
        views.product_endpoint_report, name='product_endpoint_report'),
    url(r'^engagement/(?P<eid>\d+)/report$', views.engagement_report,
        name='engagement_report'),
    url(r'^test/(?P<tid>\d+)/report$', views.test_report,
        name='test_report'),
    url(r'^endpoint/(?P<eid>\d+)/report$', views.endpoint_report,
        name='endpoint_report'),
    url(r'^product/report$',
        views.product_findings_report, name='product_findings_report'),

    # other
    url(r'^launch_va/(?P<pid>\d+)$', views.launch_va,
        name='launch_va'),

    # action history
    url(r'^history/(?P<cid>\d+)/(?P<oid>\d+)$', views.action_history,
        name='action_history'),

    # api doc urls
    url(r'api/v1/doc/',
        include('tastypie_swagger.urls', namespace='tastypie_swagger'),
        kwargs={
            "tastypie_api_module": "dojo.urls.v1_api",
            "namespace": "tastypie_swagger",
            "version": "1.0"}),

    # endpoints
    url(r'^endpoint$', views.all_endpoints,
        name='endpoints'),
    url(r'^endpoint/vulnerable$', views.vulnerable_endpoints,
        name='vulnerable_endpoints'),
    url(r'^endpoint/(?P<eid>\d+)$', views.view_endpoint,
        name='view_endpoint'),
    url(r'^endpoint/(?P<eid>\d+)/edit$', views.edit_endpoint,
        name='edit_endpoint'),
    url(r'^endpoints/(?P<pid>\d+)/add$', views.add_endpoint,
        name='add_endpoint'),
    url(r'^endpoint/(?P<eid>\d+)/delete$', views.delete_endpoint,
        name='delete_endpoint'),
    url(r'^endpoints/add$', views.add_product_endpoint,
        name='add_product_endpoint'),

]

if settings.DEBUG:
    urlpatterns += patterns('django.views.static',
                            (r'media/(?P<path>.*)', 'serve', {
                                'document_root': settings.MEDIA_ROOT}))
