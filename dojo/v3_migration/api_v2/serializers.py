from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied, ValidationError

from dojo.api_v2.serializers import ProductMetaSerializer, TagListSerializerField
from dojo.authorization.authorization import user_has_permission
from dojo.authorization.roles_permissions import Permissions
from dojo.models import (
    Dojo_User,
    Product,
    Product_API_Scan_Configuration,
    Product_Group,
    Product_Member,
    Product_Type,
    Product_Type_Group,
    Product_Type_Member,
)
from dojo.product.queries import get_authorized_products
from dojo.product_type.queries import get_authorized_product_types


class RelatedAssetField(serializers.PrimaryKeyRelatedField):
    def get_queryset(self):
        return get_authorized_products(Permissions.Product_View)


class RelatedOrganizationField(serializers.PrimaryKeyRelatedField):
    def get_queryset(self):
        return get_authorized_product_types(Permissions.Product_Type_View)


class AssetAPIScanConfigurationSerializer(serializers.ModelSerializer):
    asset = RelatedAssetField(source="product")

    class Meta:
        model = Product_API_Scan_Configuration
        exclude = ("product",)


class AssetSerializer(serializers.ModelSerializer):
    findings_count = serializers.SerializerMethodField()
    findings_list = serializers.SerializerMethodField()

    tags = TagListSerializerField(required=False)

    # V3 fields
    asset_meta = ProductMetaSerializer(source="product_meta", read_only=True, many=True)
    organization = RelatedOrganizationField(source="prod_type")
    asset_numeric_grade = serializers.IntegerField(source="prod_numeric_grade")
    enable_asset_tag_inheritance = serializers.BooleanField(source="enable_product_tag_inheritance")
    asset_managers = serializers.PrimaryKeyRelatedField(
        source="product_manager",
        queryset=Dojo_User.objects.exclude(is_active=False))

    class Meta:
        model = Product
        exclude = (
            "tid",
            "updated",
            "async_updating",
            # Below here excluded for V3 migration
            "prod_type",
            "prod_numeric_grade",
            "enable_product_tag_inheritance",
            "product_manager",
        )

    def validate(self, data):
        async_updating = getattr(self.instance, "async_updating", None)
        if async_updating:
            new_sla_config = data.get("sla_configuration", None)
            old_sla_config = getattr(self.instance, "sla_configuration", None)
            if new_sla_config and old_sla_config and new_sla_config != old_sla_config:
                msg = "Finding SLA expiration dates are currently being recalculated. The SLA configuration for this asset cannot be changed until the calculation is complete."
                raise serializers.ValidationError(msg)
        return data

    def get_findings_count(self, obj) -> int:
        return obj.findings_count

    # TODO: maybe extend_schema_field is needed here?
    def get_findings_list(self, obj) -> list[int]:
        return obj.open_findings_list()


class AssetMemberSerializer(serializers.ModelSerializer):
    asset = RelatedAssetField(source="product")

    class Meta:
        model = Product_Member
        exclude = ("product",)

    def validate(self, data):
        if (
            self.instance is not None
            and data.get("asset") != self.instance.product
            and not user_has_permission(
                self.context["request"].user,
                data.get("asset"),
                Permissions.Product_Manage_Members,
            )
        ):
            msg = "You are not permitted to add a member to this Asset"
            raise PermissionDenied(msg)

        if (
            self.instance is None
            or data.get("asset") != self.instance.product
            or data.get("user") != self.instance.user
        ):
            members = Product_Member.objects.filter(
                product=data.get("asset"), user=data.get("user"),
            )
            if members.count() > 0:
                msg = "Asset Member already exists"
                raise ValidationError(msg)

        if data.get("role").is_owner and not user_has_permission(
            self.context["request"].user,
            data.get("asset"),
            Permissions.Product_Member_Add_Owner,
        ):
            msg = "You are not permitted to add a member as Owner to this Asset"
            raise PermissionDenied(msg)

        return data


class AssetGroupSerializer(serializers.ModelSerializer):
    asset = RelatedAssetField(source="product")

    class Meta:
        model = Product_Group
        exclude = ("product",)

    def validate(self, data):
        if (
            self.instance is not None
            and data.get("asset") != self.instance.product
            and not user_has_permission(
                self.context["request"].user,
                data.get("asset"),
                Permissions.Product_Group_Add,
            )
        ):
            msg = "You are not permitted to add a group to this Asset"
            raise PermissionDenied(msg)

        if (
            self.instance is None
            or data.get("asset") != self.instance.product
            or data.get("group") != self.instance.group
        ):
            members = Product_Group.objects.filter(
                product=data.get("asset"), group=data.get("group"),
            )
            if members.count() > 0:
                msg = "Asset Group already exists"
                raise ValidationError(msg)

        if data.get("role").is_owner and not user_has_permission(
            self.context["request"].user,
            data.get("asset"),
            Permissions.Product_Group_Add_Owner,
        ):
            msg = "You are not permitted to add a group as Owner to this Asset"
            raise PermissionDenied(msg)

        return data


class OrganizationMemberSerializer(serializers.ModelSerializer):
    organization = RelatedOrganizationField(source="product_type")

    class Meta:
        model = Product_Type_Member
        exclude = ("product_type",)

    def validate(self, data):
        if (
            self.instance is not None
            and data.get("organization") != self.instance.product_type
            and not user_has_permission(
                self.context["request"].user,
                data.get("organization"),
                Permissions.Product_Type_Manage_Members,
            )
        ):
            msg = "You are not permitted to add a member to this Organization"
            raise PermissionDenied(msg)

        if (
            self.instance is None
            or data.get("organization") != self.instance.product_type
            or data.get("user") != self.instance.user
        ):
            members = Product_Type_Member.objects.filter(
                product_type=data.get("organization"), user=data.get("user"),
            )
            if members.count() > 0:
                msg = "Organization Member already exists"
                raise ValidationError(msg)

        if self.instance is not None and not data.get("role").is_owner:
            owners = (
                Product_Type_Member.objects.filter(
                    product_type=data.get("organization"), role__is_owner=True,
                )
                .exclude(id=self.instance.id)
                .count()
            )
            if owners < 1:
                msg = "There must be at least one owner"
                raise ValidationError(msg)

        if data.get("role").is_owner and not user_has_permission(
            self.context["request"].user,
            data.get("organization"),
            Permissions.Product_Type_Member_Add_Owner,
        ):
            msg = "You are not permitted to add a member as Owner to this Organization"
            raise PermissionDenied(msg)

        return data


class OrganizationGroupSerializer(serializers.ModelSerializer):
    organization = RelatedOrganizationField(source="product_type")

    class Meta:
        model = Product_Type_Group
        exclude = ("product_type",)

    def validate(self, data):
        if (
            self.instance is not None
            and data.get("organization") != self.instance.product_type
            and not user_has_permission(
                self.context["request"].user,
                data.get("organization"),
                Permissions.Product_Type_Group_Add,
            )
        ):
            msg = "You are not permitted to add a group to this Organization"
            raise PermissionDenied(msg)

        if (
            self.instance is None
            or data.get("organization") != self.instance.product_type
            or data.get("group") != self.instance.group
        ):
            members = Product_Type_Group.objects.filter(
                product_type=data.get("organization"), group=data.get("group"),
            )
            if members.count() > 0:
                msg = "Organization Group already exists"
                raise ValidationError(msg)

        if data.get("role").is_owner and not user_has_permission(
            self.context["request"].user,
            data.get("organization"),
            Permissions.Product_Type_Group_Add_Owner,
        ):
            msg = "You are not permitted to add a group as Owner to this Organization"
            raise PermissionDenied(msg)

        return data


class OrganizationSerializer(serializers.ModelSerializer):
    critical_asset = serializers.BooleanField(source="critical_product")
    key_asset = serializers.BooleanField(source="key_product")

    class Meta:
        model = Product_Type
        exclude = ("critical_product", "key_product")
