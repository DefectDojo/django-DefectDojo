from django.contrib import admin

from dojo.product.models import Product, Product_API_Scan_Configuration, Product_Line


@admin.register(Product_Line)
class ProductLineAdmin(admin.ModelAdmin):

    """Admin support for the Product_Line model."""


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):

    """Admin support for the Product model."""


@admin.register(Product_API_Scan_Configuration)
class ProductAPIScanConfigurationAdmin(admin.ModelAdmin):

    """Admin support for the Product_API_Scan_Configuration model."""
