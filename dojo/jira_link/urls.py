from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^webhook/(?P<secret>[\w-]+)$', views.webhook, name='web_hook_secret'),
    re_path(r'^webhook/', views.webhook, name='web_hook'),
    re_path(r'^jira/webhook/(?P<secret>[\w-]+)$', views.webhook, name='jira_web_hook_secret'),
    re_path(r'^jira/webhook/', views.webhook, name='jira_web_hook'),
    re_path(r'^jira/add', views.new_jira, name='add_jira'),
    re_path(r'^jira/(?P<jid>\d+)/edit$', views.edit_jira,
        name='edit_jira'),
    re_path(r'^jira/(?P<tid>\d+)/delete$', views.delete_jira,
        name='delete_jira'),
    re_path(r'^jira$', views.jira, name='jira'),
    re_path(r'^jira/express', views.express_new_jira, name='express_jira')]
