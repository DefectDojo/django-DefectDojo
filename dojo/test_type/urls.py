from django.urls import re_path

from dojo.test_type import views

urlpatterns = [
    # test types
    re_path(r'^test_type$', views.test_type, name='test_type'),
    re_path(r'^test_type/add$', views.add_test_type,
        name='add_test_type'),
    re_path(r'^test_type/(?P<ptid>\d+)/edit$',
        views.edit_test_type, name='edit_test_type'),
]
