from rest_framework import serializers

from dojo.authorization.serializer_guards import (
    AuthorizedUsersMemberGuardMixin,
    ToolConfigurationUseGuardMixin,
)
from dojo.models import (
    DojoMeta,
    Product,
    Product_API_Scan_Configuration,
    Product_Lifecycle,
    Product_Origin,
    Product_Platform,
)


class ProductMetaSerializer(serializers.ModelSerializer):
    class Meta:
        model = DojoMeta
        fields = ("name", "value")


class ProductAPIScanConfigurationSerializer(ToolConfigurationUseGuardMixin, serializers.ModelSerializer):
    class Meta:
        model = Product_API_Scan_Configuration
        fields = "__all__"


class ProductSerializer(AuthorizedUsersMemberGuardMixin, serializers.ModelSerializer):
    findings_count = serializers.SerializerMethodField()
    findings_list = serializers.SerializerMethodField()

    business_criticality = serializers.ChoiceField(choices=Product.BUSINESS_CRITICALITY_CHOICES, allow_blank=True, allow_null=True, required=False)
    # platform/lifecycle/origin are FKs to editable lookup tables. They are exposed over
    # the API by their stable ``value`` string (SlugRelatedField), so existing clients
    # and imports keep sending/receiving the same strings as before.
    platform = serializers.SlugRelatedField(slug_field="value", queryset=Product_Platform.objects.all(), allow_null=True, required=False)
    lifecycle = serializers.SlugRelatedField(slug_field="value", queryset=Product_Lifecycle.objects.all(), allow_null=True, required=False)
    origin = serializers.SlugRelatedField(slug_field="value", queryset=Product_Origin.objects.all(), allow_null=True, required=False)

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
        return data

    def get_findings_count(self, obj) -> int:
        return obj.findings_count

    # TODO: maybe extend_schema_field is needed here?
    def get_findings_list(self, obj) -> list[int]:
        return obj.open_findings_list()
