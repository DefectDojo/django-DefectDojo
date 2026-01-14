from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied, ValidationError

from dojo.authorization.authorization import user_has_permission
from dojo.authorization.roles_permissions import Permissions
from dojo.models import (
    Product_Type,
    Product_Type_Group,
    Product_Type_Member,
)
from dojo.product_type.queries import get_authorized_product_types


class RelatedOrganizationField(serializers.PrimaryKeyRelatedField):
    def get_queryset(self):
        return get_authorized_product_types(Permissions.Product_Type_View)


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
                    product_type=data.get("organization", data.get("product_type")), role__is_owner=True,
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
    critical_asset = serializers.BooleanField(source="critical_product", default=False)
    key_asset = serializers.BooleanField(source="key_product", default=False)

    class Meta:
        model = Product_Type
        exclude = ("critical_product", "key_product")
