from django.contrib import admin

from dojo.product_attributes.models import Product_Lifecycle, Product_Origin, Product_Platform

admin.site.register(Product_Platform)
admin.site.register(Product_Lifecycle)
admin.site.register(Product_Origin)
