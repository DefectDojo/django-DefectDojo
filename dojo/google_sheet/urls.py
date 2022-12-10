from django.urls import re_path

from dojo.google_sheet import views

urlpatterns = [
    #  google_sheet
    re_path(r'^configure_google_sheets$', views.configure_google_sheets,
     name='configure_google_sheets'),
    re_path(r'^export_to_sheet/(?P<tid>\d+)$', views.export_to_sheet,
     name='export_to_sheet'),
]
