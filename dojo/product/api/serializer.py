from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied

from dojo.models import DojoMeta, Product, Product_API_Scan_Configuration


class ProductMetaSerializer(serializers.ModelSerializer):
    class Meta:
        model = DojoMeta
        fields = ("name", "value")


class ProductAPIScanConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product_API_Scan_Configuration
        fields = "__all__"


class ProductSerializer(serializers.ModelSerializer):
    findings_count = serializers.SerializerMethodField()
    findings_list = serializers.SerializerMethodField()

    business_criticality = serializers.ChoiceField(choices=Product.BUSINESS_CRITICALITY_CHOICES, allow_blank=True, allow_null=True, required=False)
    platform = serializers.ChoiceField(choices=Product.PLATFORM_CHOICES, allow_blank=True, allow_null=True, required=False)
    lifecycle = serializers.ChoiceField(choices=Product.LIFECYCLE_CHOICES, allow_blank=True, allow_null=True, required=False)
    origin = serializers.ChoiceField(choices=Product.ORIGIN_CHOICES, allow_blank=True, allow_null=True, required=False)

    product_meta = ProductMetaSerializer(read_only=True, many=True)

    class Meta:
        model = Product
        exclude = (
            "tid",
            "updated",
            "async_updating",
        )

    def get_fields(self):
        from dojo.api_v2.serializers import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            TagListSerializerField,
        )
        fields = super().get_fields()
        fields["tags"] = TagListSerializerField(required=False)
        return fields

    def validate(self, data):
        async_updating = getattr(self.instance, "async_updating", None)
        if async_updating:
            new_sla_config = data.get("sla_configuration", None)
            old_sla_config = getattr(self.instance, "sla_configuration", None)
            if new_sla_config and old_sla_config and new_sla_config != old_sla_config:
                msg = "Finding SLA expiration dates are currently being recalculated. The SLA configuration for this product cannot be changed until the calculation is complete."
                raise serializers.ValidationError(msg)
        self._validate_authorized_users_change(data)
        return data

    def _validate_authorized_users_change(self, data):
        """
        Writing ``authorized_users`` is a member-management operation and is
        gated behind ``Product_Manage_Members`` -- the same permission the web
        UI requires (dojo.product.ui.views.add_product_authorized_users). The
        rest of this endpoint is governed by ``Product_Edit``, so this keeps
        changes to the membership list aligned with the dedicated
        member-management permission.

        No-ops when the field is absent or unchanged (replay-safe), mirroring
        dojo.authorization.api_permissions.check_update_permission.
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
        if not (request_user and user_has_permission(request_user, self.instance, Permissions.Product_Manage_Members)):
            msg = "You do not have permission to manage authorized users for this product."
            raise PermissionDenied(msg)

    def get_findings_count(self, obj) -> int:
        return obj.findings_count

    # TODO: maybe extend_schema_field is needed here?
    def get_findings_list(self, obj) -> list[int]:
        return obj.open_findings_list()
