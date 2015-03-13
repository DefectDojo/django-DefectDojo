from django.conf import settings
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from tastypie.api import Api
from tracker.api import UserResource, ProductResource, EngagementResource, \
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
    url(r'^$', 'tracker.views.dashboard', name='home'),
    url(r'^alerts$', 'tracker.views.alerts', name='alerts'),
    url(r'^login$', 'django.contrib.auth.views.login',
        {'template_name': 'tracker/login.html'}),
    url(r'^profile$', 'tracker.views.view_profile', name="view_profile"),
    url(r'^change_password$', 'tracker.views.change_password',
        name='change password'),
    url(r'^logout$', 'tracker.views.logout_view', name='logout'),
    url(r'^calendar$', 'tracker.views.calendar', name='calendar'),
    url(r'^simple_search$', 'tracker.views.simple_search',
        name='simple_search'),
    url(r'^api_key$', 'tracker.views.api_key', name='api_key'),
    url(r'^product$', 'tracker.views.product', name='product'),
    url(r'^all_metrics$', 'tracker.views.metrics', {'mtype': 'All'},
        name='metrics'),
    url(r'^product_type/(?P<mtype>\d+)/metrics$',
        'tracker.views.metrics', name='product_type_metrics'),
    url(r'^simple_metrics$', 'tracker.views.simple_metrics',
        name='simple_metrics'),
    url(r'^engineer_metrics$', 'tracker.views.engineer_metrics',
        name='engineer_metrics'),
    url(r'^research_metrics$', 'tracker.views.research_metrics',
        name='research_metrics'),
    url(r'^tools$', 'tracker.views.tools', name='tools'),
    url(r'^(?P<pid>\d+)/gmap$', 'tracker.views.gmap', name='gmap'),
    url(r'^product_type$', 'tracker.views.product_type', name='product_type'),
    url(r'^product_type/add$', 'tracker.views.add_product_type',
        name='add_product_type'),
    url(r'^product_type/(?P<ptid>\d+)/edit$',
        'tracker.views.edit_product_type', name='edit_product_type'),
    url(r'^product_type/(?P<ptid>\d+)/add_product',
        'tracker.views.add_product_to_product_type',
        name='add_product_to_product_type'),
    url(r'^product/add', 'tracker.views.new_product', name='new_product'),
    url(r'^product/(?P<pid>\d+)$', 'tracker.views.view_product',
        name='view_product'),
    url(r'^product/(?P<pid>\d+)/findings$',
        'tracker.views.all_product_findings', name='view_product_findings'),
    url(r'^launch_va/(?P<pid>\d+)$', 'tracker.views.launch_va',
        name='launch_va'),
    url(r'^engagements$', 'tracker.views.engagement', name='engagements'),
    url(r'^(?P<tid>\d+)/search$', 'tracker.views.search', name='search'),
    url(r'^engagement/(?P<eid>\d+)$', 'tracker.views.view_engagement',
        name='view_engagement'),
    url(r'^engagement/(?P<eid>\d+)/add_tests$', 'tracker.views.add_tests',
        name='add_tests'),
    url(r'^engagement/(?P<eid>\d+)/edit$', 'tracker.views.edit_engagement',
        name='edit_engagement'),
    url(r'^engagement/(?P<eid>\d+)/add_nessus_scan$',
        'tracker.views.add_nessus_scan', name='add_nessus_scan'),
    url(r'^engagement/(?P<eid>\d+)/close$', 'tracker.views.close_eng',
        name='close_engagement'),
    url(r'^engagement/(?P<eid>\d+)/reopen$', 'tracker.views.reopen_eng',
        name='reopen_engagement'),
    url(r'^engagement/(?P<eid>\d+)/complete_checklist$',
        'tracker.views.complete_checklist', name='complete_checklist'),
    url(r'^engagement/(?P<eid>\d+)/upload_risk_acceptance$',
        'tracker.views.upload_risk', name='upload_risk_acceptance$'),
    url(r'^engagement/(?P<eid>\d+)/risk_approval/(?P<raid>\d+)$',
        'tracker.views.view_risk', name='view_risk'),
    url(r'^engagement/(?P<eid>\d+)/risk_approval/(?P<raid>\d+)/delete$',
        'tracker.views.delete_risk', name='delete_risk'),
    url(r'^engagement/(?P<eid>\d+)/risk_approval/(?P<raid>\d+)/download$',
        'tracker.views.download_risk', name='download_risk'),
    url(r'^threatmodel/(?P<eid>\d+)$', 'tracker.views.view_threatmodel',
        name='view_threatmodel'),
    url(r'^test_type$', 'tracker.views.test_type', name='test_type'),
    url(r'^test_type/add$', 'tracker.views.add_test_type',
        name='add_test_type'),
    url(r'^test_type/(?P<ptid>\d+)/edit$',
        'tracker.views.edit_test_type', name='edit_test_type'),
    url(r'^dev_env$', 'tracker.views.dev_env', name='dev_env'),
    url(r'^dev_env/add$', 'tracker.views.add_dev_env',
        name='add_dev_env'),
    url(r'^dev_env/(?P<deid>\d+)/edit$',
        'tracker.views.edit_dev_env', name='edit_dev_env'),
    #

    url(r'^(?P<tid>\d+)/view_test$', 'tracker.views.view_test',
        name='view_test'),
    url(r'^(?P<tid>\d+)/edit_test$', 'tracker.views.edit_test',
        name='edit_test'),
    url(r'^(?P<tid>\d+)/delete_test$', 'tracker.views.delete_test',
        name='delete_test'),
    url(r'^(?P<eid>\d+)/upload_threatmodel$',
        'tracker.views.upload_threatmodel', name='upload_threatmodel'),

    url(r'^(?P<cid>\d+)/view_checklist$', 'tracker.views.view_checklist',
        name='view_checklist'),
    url(r'^open_findings$', 'tracker.views.open_findings',
        name='open_findings'),
    url(r'^closed_findings$', 'tracker.views.closed_findings',
        name='closed_findings'),
    url(r'^accepted_findings', 'tracker.views.accepted_findings',
        name='accepted_findings'),
    url(r'^(?P<sid>\d+)/view_scan$', 'tracker.views.view_scan',
        name='view_scan'),
    url(r'^(?P<sid>\d+)/view_scan_settings$',
        'tracker.views.view_scan_settings', name='view_scan_settings$'),
    url(r'^(?P<sid>\d+)/edit_scan_settings$',
        'tracker.views.edit_scan_settings', name='edit_scan_settings$'),
    url(r'^(?P<tid>\d+)/view_test/(?P<nid>\d+)/',
        'tracker.views.delete_test_note', name='delete_test_note'),
    url(r'^(?P<fid>\d+)/edit_finding$',
        'tracker.views.edit_finding', name='edit_finding'),
    url(r'^(?P<fid>\d+)/delete_finding$',
        'tracker.views.delete_finding', name='delete_finding'),
    url(r'^(?P<fid>\d+)/view_finding$', 'tracker.views.view_finding',
        name='view_finding'),
    url(r'^(?P<tid>\d+)/view_finding/(?P<nid>\d+)/',
        'tracker.views.delete_finding_note', name='delete_finding_note'),
    url(r'^(?P<fid>\d+)/close_finding$', 'tracker.views.close_finding',
        name='close_finding'),
    url(r'^(?P<fid>\d+)/mktemplate$', 'tracker.views.mktemplate',
        name='mktemplate'),
    url(r'^add_findings$', 'tracker.views.add_findings', name='add_findings'),
    url(r'^engagement/(?P<eid>\d+)/close$', 'tracker.views.close_eng',
        name='close_engagement'),
    url(r'^(?P<tid>\d+)/add_findings$', 'tracker.views.add_findings',
        name='add_findings'),
    url(r'^(?P<tid>\d+)/gen_report$', 'tracker.views.gen_report',
        name='gen_report'),
    url(r'^product/(?P<pid>\d+)/gen_report_all$',
        'tracker.views.gen_report_all', name='gen_report_all'),
    url(r'^(?P<tid>\d+)/add_findings/(?P<fid>\d+)$',
        'tracker.views.add_temp_finding', name='add_temp_finding'),
    url(r'^new_engagement$', 'tracker.views.new_engagement', name='new_eng'),
    url(r'^(?P<pid>\d+)/new_engagement$', 'tracker.views.new_eng_for_app',
        name='new_eng_for_app'),
    url(r'^(?P<pid>\d+)/edit_product$', 'tracker.views.edit_product',
        name='edit_product'),
    url(r'^(?P<eid>\d+)/view_engineer$', 'tracker.views.view_engineer',
        name='view_engineer'),
    url(r'^new_engagement/(?P<pid>\d{1})$', 'tracker.views.new_eng_for_app',
        name='new_eng_for_app'),
    url(r'^date_update/(?P<last_month>\d+)$', 'tracker.views.calc',
        name='date_update'),
    url(r'^admin/', include(admin.site.urls)),
    url(r'api/v1/doc/',
        include('tastypie_swagger.urls', namespace='tastypie_swagger'),
        kwargs={
            "tastypie_api_module": "tracker.urls.v1_api",
            "namespace": "tastypie_swagger",
            "version": "1.0"}),
)

urlpatterns += staticfiles_urlpatterns()

if settings.DEBUG:
    urlpatterns += patterns('django.views.static',
                            (r'media/(?P<path>.*)', 'serve', {
                                'document_root': settings.MEDIA_ROOT}))
