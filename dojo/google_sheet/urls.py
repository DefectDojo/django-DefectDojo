from django.conf.urls import url

from dojo.google_sheet import views

urlpatterns = [
    #  google_sheet
    url(r'^drive_configuration$', views.configure_google_drive,
     name='configure_google_drive'),
    url(r'^sync_findings/(?P<tid>\d+)/(?P<spreadsheetId>[a-zA-Z0-9-_]+)$', views.sync_findings,
     name='sync_findings'),
    url(r'^export_to_sheet/(?P<tid>\d+)$', views.export_to_sheet,
     name='export_to_sheet'),
]
