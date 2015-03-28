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
    url(r'^api/', include(v1_api.urls)),
    url(r'^$', 'dojo.views.home', name='home'),
    url(r'^dashboard$', 'dojo.views.dashboard', name='dashboard'),
    url(r'^alerts$', 'dojo.views.alerts', name='alerts'),
    url(r'^login$', 'django.contrib.auth.views.login',
        {'template_name': 'dojo/login.html'}),
    url(r'^profile$', 'dojo.views.view_profile', name="view_profile"),
    url(r'^change_password$', 'dojo.views.change_password',
        name='change password'),
    url(r'^logout$', 'dojo.views.logout_view', name='logout'),
    url(r'^calendar$', 'dojo.views.calendar', name='calendar'),
    url(r'^simple_search$', 'dojo.views.simple_search',
        name='simple_search'),
    url(r'^api_key$', 'dojo.views.api_key', name='api_key'),
    url(r'^product$', 'dojo.views.product', name='product'),
    url(r'^product/(?P<pid>\d+)/edit$', 'dojo.views.edit_product',
        name='edit_product'),

    url(r'^product/type$', 'dojo.views.product_type', name='product_type'),

    url(r'^all_metrics$', 'dojo.views.metrics', {'mtype': 'All'},
        name='metrics'),
    url(r'^product_type/(?P<mtype>\d+)/metrics$',
        'dojo.views.metrics', name='product_type_metrics'),
    url(r'^simple_metrics$', 'dojo.views.simple_metrics',
        name='simple_metrics'),
    url(r'^engineer_metrics$', 'dojo.views.engineer_metrics',
        name='engineer_metrics'),
    url(r'^research_metrics$', 'dojo.views.research_metrics',
        name='research_metrics'),
    url(r'^tools$', 'dojo.views.tools', name='tools'),
    url(r'^(?P<pid>\d+)/gmap$', 'dojo.views.gmap', name='gmap'),
    url(r'^product_type/add$', 'dojo.views.add_product_type',
        name='add_product_type'),
    url(r'^product_type/(?P<ptid>\d+)/edit$',
        'dojo.views.edit_product_type', name='edit_product_type'),
    url(r'^product_type/(?P<ptid>\d+)/add_product',
        'dojo.views.add_product_to_product_type',
        name='add_product_to_product_type'),
    url(r'^product/add', 'dojo.views.new_product', name='new_product'),
    url(r'^product/(?P<pid>\d+)$', 'dojo.views.view_product',
        name='view_product'),
    url(r'^product/(?P<pid>\d+)/findings$',
        'dojo.views.all_product_findings', name='view_product_findings'),
    url(r'^launch_va/(?P<pid>\d+)$', 'dojo.views.launch_va',
        name='launch_va'),
    url(r'^engagement$', 'dojo.views.engagement', name='engagement'),
    url(r'^(?P<tid>\d+)/search$', 'dojo.views.search', name='search'),
    url(r'^engagement/(?P<eid>\d+)$', 'dojo.views.view_engagement',
        name='view_engagement'),
    url(r'^engagement/(?P<eid>\d+)/add_tests$', 'dojo.views.add_tests',
        name='add_tests'),
    url(r'^engagement/(?P<eid>\d+)/edit$', 'dojo.views.edit_engagement',
        name='edit_engagement'),
    url(r'^engagement/(?P<eid>\d+)/add_nessus_scan$',
        'dojo.views.add_nessus_scan', name='add_nessus_scan'),
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
    url(r'^threatmodel/(?P<eid>\d+)$', 'dojo.views.view_threatmodel',
        name='view_threatmodel'),
    url(r'^test_type$', 'dojo.views.test_type', name='test_type'),
    url(r'^test_type/add$', 'dojo.views.add_test_type',
        name='add_test_type'),
    url(r'^test_type/(?P<ptid>\d+)/edit$',
        'dojo.views.edit_test_type', name='edit_test_type'),
    url(r'^dev_env$', 'dojo.views.dev_env', name='dev_env'),
    url(r'^dev_env/add$', 'dojo.views.add_dev_env',
        name='add_dev_env'),
    url(r'^dev_env/(?P<deid>\d+)/edit$',
        'dojo.views.edit_dev_env', name='edit_dev_env'),
    #

    url(r'^(?P<tid>\d+)/view_test$', 'dojo.views.view_test',
        name='view_test'),
    url(r'^(?P<tid>\d+)/edit_test$', 'dojo.views.edit_test',
        name='edit_test'),
    url(r'^(?P<tid>\d+)/delete_test$', 'dojo.views.delete_test',
        name='delete_test'),
    url(r'^(?P<eid>\d+)/upload_threatmodel$',
        'dojo.views.upload_threatmodel', name='upload_threatmodel'),

    url(r'^(?P<cid>\d+)/view_checklist$', 'dojo.views.view_checklist',
        name='view_checklist'),
    url(r'^open_findings$', 'dojo.views.open_findings',
        name='open_findings'),
    url(r'^closed_findings$', 'dojo.views.closed_findings',
        name='closed_findings'),
    url(r'^accepted_findings', 'dojo.views.accepted_findings',
        name='accepted_findings'),
    url(r'^(?P<sid>\d+)/view_scan$', 'dojo.views.view_scan',
        name='view_scan'),
    url(r'^(?P<sid>\d+)/view_scan_settings$',
        'dojo.views.view_scan_settings', name='view_scan_settings$'),
    url(r'^(?P<sid>\d+)/edit_scan_settings$',
        'dojo.views.edit_scan_settings', name='edit_scan_settings$'),
    url(r'^(?P<tid>\d+)/view_test/(?P<nid>\d+)/',
        'dojo.views.delete_test_note', name='delete_test_note'),
    url(r'^(?P<fid>\d+)/edit_finding$',
        'dojo.views.edit_finding', name='edit_finding'),
    url(r'^(?P<fid>\d+)/delete_finding$',
        'dojo.views.delete_finding', name='delete_finding'),
    url(r'^(?P<fid>\d+)/view_finding$', 'dojo.views.view_finding',
        name='view_finding'),
    url(r'^(?P<tid>\d+)/view_finding/(?P<nid>\d+)/',
        'dojo.views.delete_finding_note', name='delete_finding_note'),
    url(r'^(?P<fid>\d+)/close_finding$', 'dojo.views.close_finding',
        name='close_finding'),
    url(r'^(?P<fid>\d+)/mktemplate$', 'dojo.views.mktemplate',
        name='mktemplate'),
    url(r'^add_findings$', 'dojo.views.add_findings', name='add_findings'),
    url(r'^engagement/(?P<eid>\d+)/close$', 'dojo.views.close_eng',
        name='close_engagement'),
    url(r'^(?P<tid>\d+)/add_findings$', 'dojo.views.add_findings',
        name='add_findings'),
    url(r'^(?P<tid>\d+)/gen_report$', 'dojo.views.gen_report',
        name='gen_report'),
    url(r'^product/(?P<pid>\d+)/gen_report_all$',
        'dojo.views.gen_report_all', name='gen_report_all'),
    url(r'^(?P<tid>\d+)/add_findings/(?P<fid>\d+)$',
        'dojo.views.add_temp_finding', name='add_temp_finding'),
    url(r'^engagement/new$', 'dojo.views.new_engagement', name='new_eng'),
    url(r'^product/(?P<pid>\d+)/new_engagement$', 'dojo.views.new_eng_for_app',
        name='new_eng_for_prod'),
    url(r'^(?P<eid>\d+)/view_engineer$', 'dojo.views.view_engineer',
        name='view_engineer'),
    url(r'^new_engagement/(?P<pid>\d{1})$', 'dojo.views.new_eng_for_app',
        name='new_eng_for_app'),
    url(r'^date_update/(?P<last_month>\d+)$', 'dojo.views.calc',
        name='date_update'),
    url(r'^admin/', include(admin.site.urls)),
    url(r'api/v1/doc/',
        include('tastypie_swagger.urls', namespace='tastypie_swagger'),
        kwargs={
            "tastypie_api_module": "dojo.urls.v1_api",
            "namespace": "tastypie_swagger",
            "version": "1.0"}),
)

urlpatterns += staticfiles_urlpatterns()

if settings.DEBUG:
    urlpatterns += patterns('django.views.static',
                            (r'media/(?P<path>.*)', 'serve', {
                                'document_root': settings.MEDIA_ROOT}))
