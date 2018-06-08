from django.conf.urls import url
import views

urlpatterns = [
    url(r'^webhook', views.webhook, name='web_hook'),
    url(r'^jira/add', views.new_jira, name='add_jira'),
    url(r'^jira/(?P<jid>\d+)/edit$', views.edit_jira,
        name='edit_jira'),
    url(r'^jira/(?P<tid>\d+)/delete$', views.delete_jira,
        name='delete_jira'),
    url(r'^jira$', views.jira, name='jira'), ]
