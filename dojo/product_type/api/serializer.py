from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied

from dojo.product_type.models import Product_Type


class ProductTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product_Type
        fields = "__all__"

    def validate(self, data):
        self._validate_authorized_users_change(data)
        return data

    def _validate_authorized_users_change(self, data):
        """
        Changing ``authorized_users`` requires ``Product_Type_Manage_Members``;
        all other fields on this serializer require ``Product_Type_Edit``. No-op
        when the field is absent or unchanged (replay-safe). Mirrors
        dojo.product.api.serializer.ProductSerializer.
        """
        if "authorized_users" not in data:
            return

        # Field-level validation has already resolved the payload to Dojo_User
        # instances at this point.
        from dojo.authorization.authorization import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            user_has_permission,
        )
        from dojo.authorization.roles_permissions import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            Permissions,
        )

        new_ids = sorted(user.pk for user in (data.get("authorized_users") or []))
        current_ids = (
            sorted(self.instance.authorized_users.values_list("pk", flat=True))
            if self.instance is not None
            else []
        )
        if new_ids == current_ids:
            return

        request = self.context.get("request")
        request_user = getattr(request, "user", None)
        if not (
            request_user
            and user_has_permission(request_user, self.instance, Permissions.Product_Type_Manage_Members)
        ):
            msg = "You do not have permission to manage authorized users for this product type."
            raise PermissionDenied(msg)
