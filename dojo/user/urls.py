from django.conf.urls import url, include

from dojo.user import views

urlpatterns = [
    # social-auth-django required url package
    url('', include('social_django.urls', namespace='social')),
    #  user specific
    url(r'^login$', views.login_view, name='login'),
    url(r'^logout$', views.logout_view, name='logout'),
    url(r'^alerts$', views.alerts, name='alerts'),
    url(r'^alerts/json$', views.alerts_json, name='alerts_json'),
    url(r'^alerts/count$', views.alertcount, name='alertcount'),
    url(r'^delete_alerts$', views.delete_alerts, name='delete_alerts'),
    url(r'^profile$', views.view_profile, name='view_profile'),
    url(r'^change_password$', views.change_password,
        name='change_password'),
    url(r'^user$', views.user, name='users'),
    url(r'^group$', views.group, name='groups'),
    url(r'^group/(?P<gid>\d+)$', views.view_group,
        name='view_group'),
    url(r'^group/(?P<gid>\d+)/edit$', views.edit_group,
        name='edit_group'),
    url(r'^group/(?P<gid>\d+)/delete', views.delete_group,
        name='delete_group'),
    url(r'^group/add$', views.add_group, name='add_group'),
    url(r'^user/add$', views.add_user, name='add_user'),
    url(r'^user/(?P<uid>\d+)$', views.view_user,
        name='view_user'),
    url(r'^user/(?P<uid>\d+)/edit$', views.edit_user,
        name='edit_user'),
    url(r'^user/(?P<uid>\d+)/delete', views.delete_user,
        name='delete_user'),
    url(r'^api/key$', views.api_key, name='api_key'),
    url(r'^api/key-v2$', views.api_v2_key, name='api_v2_key'),
    url(r'^user/(?P<uid>\d+)/add_product_type_member$', views.add_product_type_member,
        name='add_product_type_member_user'),
    url(r'^user/(?P<uid>\d+)/add_product_member$', views.add_product_member,
        name='add_product_member_user'),
]
