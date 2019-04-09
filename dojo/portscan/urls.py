from django.conf.urls import url

from dojo.portscan import views

urlpatterns = [
    # scans and scan settings
    url(r'^portscan/(?P<sid>\d+)$', views.view_portscan,
        name='view_portscan'),
    url(r'^product/(?P<pid>\d+)/portscan/add$', views.gmap, name='gmap'),
    url(r'^product/(?P<pid>\d+)/portscan/(?P<sid>\d+)/settings$',
        views.view_portscan_settings, name='view_portscan_settings'),
    url(r'^product/(?P<pid>\d+)/portscan/(?P<sid>\d+)/edit$',
        views.edit_portscan_settings, name='edit_portscan_settings'),
]
