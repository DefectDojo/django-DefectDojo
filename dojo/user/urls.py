from django.conf.urls import include
from django.urls import re_path
from django.contrib.auth import views as auth_views
from django.conf import settings

from dojo.user import views

urlpatterns = [
    # social-auth-django required url package
    re_path('', include('social_django.urls', namespace='social')),
    #  user specific
    re_path(r'^login$', views.login_view, name='login'),
    re_path(r'^logout$', views.logout_view, name='logout'),
    re_path(r'^alerts$', views.alerts, name='alerts'),
    re_path(r'^alerts/json$', views.alerts_json, name='alerts_json'),
    re_path(r'^alerts/count$', views.alertcount, name='alertcount'),
    re_path(r'^delete_alerts$', views.delete_alerts, name='delete_alerts'),
    re_path(r'^profile$', views.view_profile, name='view_profile'),
    re_path(r'^change_password$', views.change_password, name='change_password'),
    re_path(r'^user$', views.user, name='users'),
    re_path(r'^user/add$', views.add_user, name='add_user'),
    re_path(r'^user/(?P<uid>\d+)$', views.view_user, name='view_user'),
    re_path(r'^user/(?P<uid>\d+)/edit$', views.edit_user, name='edit_user'),
    re_path(r'^user/(?P<uid>\d+)/delete', views.delete_user, name='delete_user'),
    re_path(r'^user/(?P<uid>\d+)/add_product_type_member$', views.add_product_type_member, name='add_product_type_member_user'),
    re_path(r'^user/(?P<uid>\d+)/add_product_member$', views.add_product_member, name='add_product_member_user'),
    re_path(r'^user/(?P<uid>\d+)/add_group_member$', views.add_group_member, name='add_group_member_user'),
    re_path(r'^user/(?P<uid>\d+)/edit_permissions$', views.edit_permissions, name='edit_user_permissions')
]
if settings.FORGOT_PASSWORD:
    urlpatterns.extend([
        re_path(r'^password_reset/$', views.DojoPasswordResetView.as_view(
            template_name='dojo/password_reset.html',
        ), name="password_reset"),
        re_path(r'^password_reset/done/$', auth_views.PasswordResetDoneView.as_view(
            template_name='dojo/password_reset_done.html',
        ), name='password_reset_done'),
        re_path(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,40})/$', auth_views.PasswordResetConfirmView.as_view(
            template_name='dojo/password_reset_confirm.html',
        ), name='password_reset_confirm'),
        re_path(r'^reset/done/$', auth_views.PasswordResetCompleteView.as_view(
            template_name='dojo/password_reset_complete.html',
        ), name='password_reset_complete'),
    ])

if settings.API_TOKENS_ENABLED:
    urlpatterns += [re_path(r'^api/key-v2$', views.api_v2_key, name='api_v2_key')]
