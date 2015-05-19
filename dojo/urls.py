from django.conf import settings
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from tastypie.api import Api
from dojo.api import UserResource, ProductResource, EngagementResource, \
    TestResource, FindingResource, ScanSettingsResource, ScanResource
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


urlpatterns = patterns(
    '',
    #  django admin
    url(r'^admin/', include(admin.site.urls)),

    #  dojo home pages
    url(r'^$', 'dojo.views.home', name='home'),
    url(r'^dashboard$', 'dojo.views.dashboard', name='dashboard'),

    #  tastypie api
    url(r'^api/', include(v1_api.urls)),
    url(r'^api/key$', 'dojo.views.api_key', name='api_key'),

    #  user specific
    url(r'^login$', 'django.contrib.auth.views.login',
        {'template_name': 'dojo/login.html'}, name='login'),
    url(r'^logout$', 'dojo.views.logout_view', name='logout'),
    url(r'^alerts$', 'dojo.views.alerts', name='alerts'),
    url(r'^profile$', 'dojo.views.view_profile', name='view_profile'),
    url(r'^change_password$', 'dojo.views.change_password',
        name='change_password'),

    #  search
    url(r'^simple_search$', 'dojo.views.simple_search',
        name='simple_search'),

    # calendar
    url(r'^calendar$', 'dojo.views.calendar', name='calendar'),
    # url(r'^date_update/(?P<last_month>\d+)$', 'dojo.views.calc',
    #     name='date_update'),

    #  product
    url(r'^product$', 'dojo.views.product', name='product'),
    url(r'^product/(?P<pid>\d+)$', 'dojo.views.view_product',
        name='view_product'),
    url(r'^product/(?P<pid>\d+)/edit$', 'dojo.views.edit_product',
        name='edit_product'),
    url(r'^product/(?P<pid>\d+)/delete$', 'dojo.views.delete_product',
        name='delete_product'),
    url(r'^product/add', 'dojo.views.new_product', name='new_product'),
    url(r'^product/(?P<pid>\d+)/findings$',
        'dojo.views.all_product_findings', name='view_product_findings'),
    url(r'^product/(?P<pid>\d+)/new_engagement$', 'dojo.views.new_eng_for_app',
        name='new_eng_for_prod'),

    #  product type
    url(r'^product/type$', 'dojo.views.product_type', name='product_type'),
    url(r'^product/type/(?P<ptid>\d+)/edit$',
        'dojo.views.edit_product_type', name='edit_product_type'),
    url(r'^product/type/add$', 'dojo.views.add_product_type',
        name='add_product_type'),
    url(r'^product/type/(?P<ptid>\d+)/add_product',
        'dojo.views.add_product_to_product_type',
        name='add_product_to_product_type'),

    #  engagements
    url(r'^engagement$', 'dojo.views.engagement', name='engagement'),
    url(r'^engagement/new$', 'dojo.views.new_engagement', name='new_eng'),
    url(r'^engagement/(?P<eid>\d+)$', 'dojo.views.view_engagement',
        name='view_engagement'),
    url(r'^engagement/(?P<eid>\d+)/edit$', 'dojo.views.edit_engagement',
        name='edit_engagement'),
    url(r'^engagement/(?P<eid>\d+)/delete$', 'dojo.views.delete_engagement',
        name='delete_engagement'),
    url(r'^engagement/(?P<eid>\d+)/add_tests$', 'dojo.views.add_tests',
        name='add_tests'),
    url(r'^engagement/(?P<eid>\d+)/add_nessus_scan$',
        'dojo.views.add_nessus_scan', name='add_nessus_scan'),
    url(r'^engagement/(?P<eid>\d+)/add_veracode_scan$',
        'dojo.views.add_veracode_scan', name='add_veracode_scan'),
    url(r'^engagement/(?P<eid>\d+)/add_burp_scan$',
        'dojo.views.add_burp_scan', name='add_burp_scan'),
    url(r'^engagement/(?P<eid>\d+)/close$', 'dojo.views.close_eng',
        name='close_engagement'),
    url(r'^engagement/(?P<eid>\d+)/reopen$', 'dojo.views.reopen_eng',
        name='reopen_engagement'),
    url(r'^engagement/(?P<eid>\d+)/complete_checklist$',
        'dojo.views.complete_checklist', name='complete_checklist'),
    url(r'^engagement/(?P<eid>\d+)/upload_risk_acceptance$',
        'dojo.views.upload_risk', name='upload_risk_acceptance$'),
    url(r'^engagement/(?P<eid>\d+)/risk_approval/(?P<raid>\d+)$',
        'dojo.views.view_risk', name='view_risk'),
    url(r'^engagement/(?P<eid>\d+)/risk_approval/(?P<raid>\d+)/delete$',
        'dojo.views.delete_risk', name='delete_risk'),
    url(r'^engagement/(?P<eid>\d+)/risk_approval/(?P<raid>\d+)/download$',
        'dojo.views.download_risk', name='download_risk'),
    url(r'^engagement/(?P<eid>\d+)/threatmodel$', 'dojo.views.view_threatmodel',
        name='view_threatmodel'),
    url(r'^engagement/(?P<eid>\d+)/threatmodel/upload$',
        'dojo.views.upload_threatmodel', name='upload_threatmodel'),


    #  findings
    url(r'^finding$', 'dojo.views.open_findings',
        name='findings'),
    url(r'^finding/open$', 'dojo.views.open_findings',
        name='open_findings'),
    url(r'^finding/closed$', 'dojo.views.closed_findings',
        name='closed_findings'),
    url(r'^finding/accepted', 'dojo.views.accepted_findings',
        name='accepted_findings'),
    url(r'^finding/(?P<fid>\d+)$', 'dojo.views.view_finding',
        name='view_finding'),
    url(r'^finding/(?P<fid>\d+)/edit$',
        'dojo.views.edit_finding', name='edit_finding'),
    url(r'^finding/(?P<fid>\d+)/delete$',
        'dojo.views.delete_finding', name='delete_finding'),
    url(r'^finding/(?P<fid>\d+)/mktemplate$', 'dojo.views.mktemplate',
        name='mktemplate'),
    url(r'^finding/(?P<fid>\d+)/close$', 'dojo.views.close_finding',
        name='close_finding'),
    url(r'^finding/(?P<tid>\d+)/note/(?P<nid>\d+)/delete$',
        'dojo.views.delete_finding_note', name='delete_finding_note'),

    #  metrics
    url(r'^metrics$', 'dojo.views.metrics', {'mtype': 'All'},
        name='metrics'),
    url(r'^metrics/all$', 'dojo.views.metrics', {'mtype': 'All'},
        name='metrics_all'),
    url(r'^metrics/simple$', 'dojo.views.simple_metrics',
        name='simple_metrics'),
    url(r'^metrics/product/type/(?P<mtype>\d+)$',
        'dojo.views.metrics', name='product_type_metrics'),
    url(r'^metrics/engineer$', 'dojo.views.engineer_metrics',
        name='engineer_metrics'),
    url(r'^metrics/research$', 'dojo.views.research_metrics',
        name='research_metrics'),
    url(r'^metrics/engineer/(?P<eid>\d+)$', 'dojo.views.view_engineer',
        name='view_engineer'),

    # test types
    url(r'^test_type$', 'dojo.views.test_type', name='test_type'),
    url(r'^test_type/add$', 'dojo.views.add_test_type',
        name='add_test_type'),
    url(r'^test_type/(?P<ptid>\d+)/edit$',
        'dojo.views.edit_test_type', name='edit_test_type'),

    #dev envs
    url(r'^dev_env$', 'dojo.views.dev_env', name='dev_env'),
    url(r'^dev_env/add$', 'dojo.views.add_dev_env',
        name='add_dev_env'),
    url(r'^dev_env/(?P<deid>\d+)/edit$',
        'dojo.views.edit_dev_env', name='edit_dev_env'),

    #  tests
    url(r'^test/(?P<tid>\d+)$', 'dojo.views.view_test',
        name='view_test'),
    url(r'^test/(?P<tid>\d+)/edit$', 'dojo.views.edit_test',
        name='edit_test'),
    url(r'^test/(?P<tid>\d+)/delete$', 'dojo.views.delete_test',
        name='delete_test'),
    url(r'^test/(?P<tid>\d+)/add_findings$', 'dojo.views.add_findings',
        name='add_findings'),
    url(r'^test/(?P<tid>\d+)/add_findings/(?P<fid>\d+)$',
        'dojo.views.add_temp_finding', name='add_temp_finding'),
    url(r'^test/(?P<tid>\d+)/note/(?P<nid>\d+)/delete$',
        'dojo.views.delete_test_note', name='delete_test_note'),
    url(r'^test/(?P<tid>\d+)/search$', 'dojo.views.search', name='search'),

    # scans and scan settings
    url(r'^scan/(?P<sid>\d+)$', 'dojo.views.view_scan',
        name='view_scan'),
    url(r'^product/(?P<pid>\d+)/scan/add$', 'dojo.views.gmap', name='gmap'),
    url(r'^product/(?P<pid>\d+)/scan/(?P<sid>\d+)/settings$',
        'dojo.views.view_scan_settings', name='view_scan_settings'),
    url(r'^product/(?P<pid>\d+)/scan/(?P<sid>\d+)/edit$',
        'dojo.views.edit_scan_settings', name='edit_scan_settings'),

    #  reports
    url(r'^product/type/(?P<ptid>\d+)/report$',
        'dojo.views.product_type_report', name='product_type_report'),
    url(r'^product/(?P<pid>\d+)/report$',
        'dojo.views.product_report', name='product_report'),
    url(r'^engagement/(?P<eid>\d+)/report$', 'dojo.views.engagement_report',
        name='engagement_report'),
    url(r'^test/(?P<tid>\d+)/report$', 'dojo.views.test_report',
        name='test_report'),
    url(r'^endpoint/(?P<eid>\d+)/report$', 'dojo.views.endpoint_report',
        name='endpoint_report'),
    url(r'^product/report$',
        'dojo.views.product_findings_report', name='product_findings_report'),

    # other
    url(r'^launch_va/(?P<pid>\d+)$', 'dojo.views.launch_va',
        name='launch_va'),

    # api doc urls
    url(r'api/v1/doc/',
        include('tastypie_swagger.urls', namespace='tastypie_swagger'),
        kwargs={
            "tastypie_api_module": "dojo.urls.v1_api",
            "namespace": "tastypie_swagger",
            "version": "1.0"}),

    # endpoints
    url(r'^endpoint$', 'dojo.views.all_endpoints',
        name='endpoints'),
    url(r'^endpoint/vulnerable$', 'dojo.views.vulnerable_endpoints',
        name='vulnerable_endpoints'),
    url(r'^endpoint/(?P<eid>\d+)$', 'dojo.views.view_endpoint',
        name='view_endpoint'),
    url(r'^endpoint/(?P<eid>\d+)/edit$', 'dojo.views.edit_endpoint',
        name='edit_endpoint'),
    url(r'^endpoints/(?P<pid>\d+)/add$', 'dojo.views.add_endpoint',
        name='add_endpoint'),
    url(r'^endpoint/(?P<eid>\d+)/delete$', 'dojo.views.delete_endpoint',
        name='delete_endpoint'),
    url(r'^endpoints/add$', 'dojo.views.add_product_endpoint',
        name='add_product_endpoint'),

)

urlpatterns += staticfiles_urlpatterns()

if settings.DEBUG:
    urlpatterns += patterns('django.views.static',
                            (r'media/(?P<path>.*)', 'serve', {
                                'document_root': settings.MEDIA_ROOT}))
