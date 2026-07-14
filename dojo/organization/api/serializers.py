from rest_framework import serializers

from dojo.models import Product_Type
from dojo.product_type.queries import get_authorized_product_types


class RelatedOrganizationField(serializers.PrimaryKeyRelatedField):
    def get_queryset(self):
        return get_authorized_product_types("view")


class OrganizationSerializer(serializers.ModelSerializer):
    critical_asset = serializers.BooleanField(source="critical_product", default=False)
    key_asset = serializers.BooleanField(source="key_product", default=False)

    class Meta:
        model = Product_Type
        exclude = ("critical_product", "key_product")
