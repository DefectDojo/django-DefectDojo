from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^cred/add', views.new_cred, name='add_cred'),
    re_path(r'^cred/(?P<ttid>\d+)/view$', views.view_cred_details, name='view_cred_details'),
    re_path(r'^cred/(?P<ttid>\d+)/edit$', views.edit_cred, name='edit_cred'),
    re_path(r'^cred/(?P<ttid>\d+)/delete$', views.delete_cred, name='delete_cred'),
    re_path(r'^cred$', views.cred, name='cred'),
    re_path(r'^product/(?P<pid>\d+)/cred/add$', views.new_cred_product, name='new_cred_product'),
    re_path(r'^product/(?P<pid>\d+)/cred/all$', views.all_cred_product, name='all_cred_product'),
    re_path(r'^product/(?P<pid>\d+)/cred/(?P<ttid>\d+)/edit$', views.edit_cred_product, name='edit_cred_product'),
    re_path(r'^product/(?P<pid>\d+)/cred/(?P<ttid>\d+)/view$', views.view_cred_product, name='view_cred_product'),
    re_path(r'^product/(?P<pid>\d+)/cred/(?P<ttid>\d+)/delete$', views.delete_cred_product, name='delete_cred_product'),
    re_path(r'^engagement/(?P<eid>\d+)/cred/add$', views.new_cred_product_engagement, name='new_cred_product_engagement'),
    re_path(r'^engagement/(?P<eid>\d+)/cred/(?P<ttid>\d+)/view$', views.view_cred_product_engagement,
        name='view_cred_product_engagement'),
    re_path(r'^engagement/(?P<eid>\d+)/cred/(?P<ttid>\d+)/delete$', views.delete_cred_engagement,
        name='delete_cred_engagement'),
    re_path(r'^test/(?P<tid>\d+)/cred/add$', views.new_cred_engagement_test, name='new_cred_engagement_test'),
    re_path(r'^test/(?P<tid>\d+)/cred/(?P<ttid>\d+)/view$', views.view_cred_engagement_test,
        name='view_cred_engagement_test'),
    re_path(r'^test/(?P<tid>\d+)/cred/(?P<ttid>\d+)/delete$', views.delete_cred_test, name='delete_cred_test'),
    re_path(r'^finding/(?P<fid>\d+)/cred/add$', views.new_cred_finding, name='new_cred_finding'),
    re_path(r'^finding/(?P<fid>\d+)/cred/(?P<ttid>\d+)/view$', views.view_cred_finding, name='view_cred_finding'),
    re_path(r'^finding/(?P<fid>\d+)/cred/(?P<ttid>\d+)/delete$', views.delete_cred_finding, name='delete_cred_finding'),
]
