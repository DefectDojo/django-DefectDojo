from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^benchmark/(?P<pid>\d+)/type/(?P<type>\d+)$', views.benchmark_view, name='view_product_benchmark'),
    re_path(r'^benchmark/(?P<pid>\d+)/type/(?P<type>\d+)/category/(?P<cat>\d+)$', views.benchmark_view, name='view_product_benchmark'),
    re_path(r'^benchmark/(?P<pid>\d+)/type/(?P<type>\d+)/category/(?P<cat>\d+)/edit/(?P<bid>\d+)$', views.benchmark_view, name='edit_benchmark'),
    re_path(r'^benchmark/(?P<pid>\d+)/type/(?P<type>\d+)/delete$', views.delete, name='delete_product_benchmark')
]
