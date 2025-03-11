from django.urls import re_path

from . import views

urlpatterns = [
    re_path(
        r"^benchmark/(?P<pid>\d+)/type/(?P<benchmark_type>\d+)$",
        views.benchmark_view,
        name="view_product_benchmark",
    ),
    re_path(
        r"^benchmark/(?P<pid>\d+)/type/(?P<benchmark_type>\d+)/category/(?P<cat>\d+)$",
        views.benchmark_view,
        name="view_product_benchmark",
    ),
    re_path(
        r"^benchmark/(?P<pid>\d+)/type/(?P<benchmark_type>\d+)/category/(?P<cat>\d+)/edit/(?P<bid>\d+)$",
        views.benchmark_view,
        name="edit_benchmark",
    ),
    re_path(
        r"^benchmark/(?P<pid>\d+)/type/(?P<benchmark_type>\d+)/delete$",
        views.delete,
        name="delete_product_benchmark",
    ),
    re_path(
        r"^benchmark/(?P<pid>\d+)/type/(?P<_type>\d+)/update$",
        views.update_benchmark,
        name="update_product_benchmark",
    ),
    re_path(
        r"^benchmark/(?P<pid>\d+)/type/(?P<_type>\d+)/summary/(?P<summary>\d+)/update$",
        views.update_benchmark_summary,
        name="update_product_benchmark_summary",
    ),
]
