from rest_framework import serializers

from dojo.product_type.models import Product_Type


class ProductTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product_Type
        fields = "__all__"
