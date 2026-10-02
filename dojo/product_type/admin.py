from django.contrib import admin

from dojo.product_type.models import Product_Type


@admin.register(Product_Type)
class Product_TypeAdmin(admin.ModelAdmin):

    """Admin support for the Product_Type model."""
