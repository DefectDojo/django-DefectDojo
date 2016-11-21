from django.conf.urls import patterns, url
from django.contrib import admin
from django.apps import apps
import views

urlpatterns = patterns(
'',
url(r'^webhook', views.webhook, name='web_hook'),
url(r'^jira/add', views.new_jira, name='add_jira'),
url(r'^jira/(?P<jid>\d+)/edit$', views.edit_jira,
     name='edit_jira'),
url(r'^jira$', views.jira, name='jira'),)
