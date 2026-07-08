from rest_framework import serializers

from dojo.authorization.authorization import raise_if_unauthorized_authorized_users_change
from dojo.authorization.roles_permissions import Permissions
from dojo.product_type.models import Product_Type


class ProductTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product_Type
        fields = "__all__"

    def validate(self, data):
        raise_if_unauthorized_authorized_users_change(self, data, Permissions.Product_Type_Manage_Members)
        return data
