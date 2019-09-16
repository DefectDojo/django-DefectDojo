from django.conf.urls import url

from dojo.google_sheet import views

urlpatterns = [
    #  google_sheet
    url(r'^googlesheet$', views.connect_to_google_apis,
     name='connect_to_google_apis'),
    url(r'^drive_authentication$', views.drive_authentication,
     name='drive_authentication'),
    url(r'^oauth2callback$', views.oauth2callback,
     name='oauth2callback'),
]
