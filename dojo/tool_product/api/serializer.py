from rest_framework import serializers

from dojo.models import Product
from dojo.tool_product.models import Tool_Product_Settings


class ToolProductSettingsSerializer(serializers.ModelSerializer):
    setting_url = serializers.CharField(source="url")
    product = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(), required=True,
    )

    class Meta:
        model = Tool_Product_Settings
        fields = "__all__"
