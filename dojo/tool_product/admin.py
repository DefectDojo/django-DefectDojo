from django.contrib import admin

from dojo.tool_product.models import Tool_Product_History, Tool_Product_Settings

admin.site.register(Tool_Product_Settings)
admin.site.register(Tool_Product_History)
