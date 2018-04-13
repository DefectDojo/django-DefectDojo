from django.conf.urls import url
from django.contrib import admin
from django.apps import apps
import views

urlpatterns = [
    url(r'^benchmark/(?P<pid>\d+)/type/(?P<type>\d+)$', views.benchmark_view, name='view_product_benchmark'),
    url(r'^benchmark/(?P<pid>\d+)/type/(?P<type>\d+)/category/(?P<cat>\d+)', views.benchmark_view, name='view_product_benchmark')
    ]
