from django.conf.urls import url
import views

urlpatterns = [
    url(r'^rules', views.rules, name='Rules Framework'),
    url(r'^rules/add', views.new_jira, name='Add Rule'),
    url(r'^rule/(?P<pid>\d+)/edit$', views.edit_rule,
        name='Edit Rule'),
    url(r'^rule/(?P<tid>\d+)/delete$', views.delete_rule,
        name='Delete Rule'), ]
