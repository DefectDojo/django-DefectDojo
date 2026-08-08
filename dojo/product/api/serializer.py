from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied

from dojo.authorization.serializer_guards import AuthorizedUsersMemberGuardMixin
from dojo.models import DojoMeta, Product, Product_API_Scan_Configuration
from dojo.tool_config.queries import get_authorized_tool_configurations


class ProductMetaSerializer(serializers.ModelSerializer):
    class Meta:
        model = DojoMeta
        fields = ("name", "value")


class ProductAPIScanConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product_API_Scan_Configuration
        fields = "__all__"

    def validate(self, data):
        self._validate_tool_configuration_use(data)
        return data

    def _validate_tool_configuration_use(self, data):
        """
        Selecting a ``tool_configuration`` lets an import run authenticated
        requests with the credential stored on it, so it is gated by the same
        ``view_tool_configuration`` permission that guards the tool-configuration
        views -- not just the product permission this endpoint already checks.

        No-ops when the field is absent (replay-safe on PATCH), mirroring
        dojo.authorization.api_permissions.check_update_permission.
        """
        if "tool_configuration" not in data:
            return
        tool_configuration = data.get("tool_configuration")
        request = self.context.get("request")
        request_user = getattr(request, "user", None)
        if tool_configuration is not None and not get_authorized_tool_configurations(request_user).filter(pk=tool_configuration.pk).exists():
            msg = "You do not have permission to use this tool configuration."
            raise PermissionDenied(msg)


class ProductSerializer(AuthorizedUsersMemberGuardMixin, serializers.ModelSerializer):
    findings_count = serializers.SerializerMethodField()
    findings_list = serializers.SerializerMethodField()
    github_project = serializers.CharField(allow_blank=True, max_length=200, required=False, write_only=True)
    github_configuration = serializers.PrimaryKeyRelatedField(
        allow_null=True,
        queryset=GITHUB_Conf.objects.all(),
        required=False,
        write_only=True,
    )

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

    def create(self, validated_data):
        github_project = validated_data.pop("github_project", "")
        github_configuration = validated_data.pop("github_configuration", None)
        product = super().create(validated_data)
        if github_project or github_configuration:
            GITHUB_PKey.objects.create(
                product=product,
                git_project=github_project,
                git_conf=github_configuration,
            )
        return product

    def validate(self, data):
        async_updating = getattr(self.instance, "async_updating", None)
        if async_updating:
            new_sla_config = data.get("sla_configuration", None)
            old_sla_config = getattr(self.instance, "sla_configuration", None)
            if new_sla_config and old_sla_config and new_sla_config != old_sla_config:
                msg = "Finding SLA expiration dates are currently being recalculated. The SLA configuration for this product cannot be changed until the calculation is complete."
                raise serializers.ValidationError(msg)
        return data

    def get_findings_count(self, obj) -> int:
        return obj.findings_count

    # TODO: maybe extend_schema_field is needed here?
    def get_findings_list(self, obj) -> list[int]:
        return obj.open_findings_list()
