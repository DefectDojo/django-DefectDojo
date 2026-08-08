from django.contrib import admin

from dojo.benchmark.models import (
    Benchmark_Category,
    Benchmark_Product,
    Benchmark_Product_Summary,
    Benchmark_Requirement,
    Benchmark_Type,
)

admin.site.register(Benchmark_Type)
admin.site.register(Benchmark_Requirement)
admin.site.register(Benchmark_Category)
admin.site.register(Benchmark_Product)
admin.site.register(Benchmark_Product_Summary)
