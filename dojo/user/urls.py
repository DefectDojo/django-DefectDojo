from django.conf.urls import url, include
from django.contrib.auth import views as auth_views
from django.conf import settings

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
    url(r'^user/add$', views.add_user, name='add_user'),
    url(r'^user/(?P<uid>\d+)$', views.view_user,
        name='view_user'),
    url(r'^user/(?P<uid>\d+)/edit$', views.edit_user,
        name='edit_user'),
    url(r'^user/(?P<uid>\d+)/delete', views.delete_user,
        name='delete_user'),
    url(r'^api/key-v2$', views.api_v2_key, name='api_v2_key'),
    url(r'^user/(?P<uid>\d+)/add_product_type_member$', views.add_product_type_member,
        name='add_product_type_member_user'),
    url(r'^user/(?P<uid>\d+)/add_product_member$', views.add_product_member,
        name='add_product_member_user'),
    url(r'^user/(?P<uid>\d+)/add_group_member$', views.add_group_member,
        name='add_group_member_user'),
    url(r'^user/(?P<uid>\d+)/edit_permissions$', views.edit_permissions,
        name='edit_user_permissions')
]
if settings.FORGOT_PASSWORD:
    urlpatterns.extend([
        url(r'^password_reset/$', views.DojoPasswordResetView.as_view(
            template_name='dojo/password_reset.html',
        ), name="password_reset"),
        url(r'^password_reset/done/$', auth_views.PasswordResetDoneView.as_view(
            template_name='dojo/password_reset_done.html',
        ), name='password_reset_done'),
        url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,40})/$', auth_views.PasswordResetConfirmView.as_view(
            template_name='dojo/password_reset_confirm.html',
        ), name='password_reset_confirm'),
        url(r'^reset/done/$', auth_views.PasswordResetCompleteView.as_view(
            template_name='dojo/password_reset_complete.html',
        ), name='password_reset_complete'),
    ])
