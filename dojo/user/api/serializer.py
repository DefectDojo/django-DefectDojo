from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from dojo.models import Dojo_User, UserContactInfo
from dojo.user.utils import get_configuration_permissions_codenames

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    date_joined = serializers.DateTimeField(read_only=True)
    last_login = serializers.DateTimeField(read_only=True, allow_null=True)
    email = serializers.EmailField(required=True)
    token_last_reset = serializers.SerializerMethodField()
    password_last_reset = serializers.SerializerMethodField()
    password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
        required=False,
        validators=[validate_password],
    )
    configuration_permissions = serializers.PrimaryKeyRelatedField(
        allow_null=True,
        queryset=Permission.objects.filter(
            codename__in=get_configuration_permissions_codenames(),
        ),
        many=True,
        required=False,
        source="user_permissions",
    )

    class Meta:
        model = Dojo_User
        fields = (
            "id",
            "username",
            "first_name",
            "last_name",
            "email",
            "date_joined",
            "last_login",
            "is_active",
            "is_staff",
            "is_superuser",
            "token_last_reset",
            "password_last_reset",
            "password",
            "configuration_permissions",
        )

    @extend_schema_field(serializers.DateTimeField(allow_null=True))
    def get_token_last_reset(self, instance):
        uci = getattr(instance, "usercontactinfo", None)
        return getattr(uci, "token_last_reset", None)

    @extend_schema_field(serializers.DateTimeField(allow_null=True))
    def get_password_last_reset(self, instance):
        uci = getattr(instance, "usercontactinfo", None)
        return getattr(uci, "password_last_reset", None)

    def to_representation(self, instance):
        ret = super().to_representation(instance)

        # This will show only "configuration_permissions" even if user has also
        # other permissions
        all_permissions = set(ret["configuration_permissions"])
        allowed_configuration_permissions = set(
            self.fields[
                "configuration_permissions"
            ].child_relation.queryset.values_list("id", flat=True),
        )
        ret["configuration_permissions"] = list(
            all_permissions.intersection(allowed_configuration_permissions),
        )

        return ret

    def update(self, instance, validated_data):
        permissions_in_payload = None
        new_configuration_permissions = None
        if (
            "user_permissions" in validated_data
        ):  # This field was renamed from "configuration_permissions" in the meantime
            permissions_in_payload = validated_data.pop("user_permissions")
            new_configuration_permissions = set(permissions_in_payload)

        instance = super().update(instance, validated_data)

        # This will update only Permissions from category
        # "configuration_permissions". Others will be untouched
        if new_configuration_permissions:
            allowed_configuration_permissions = set(
                self.fields[
                    "configuration_permissions"
                ].child_relation.queryset.all(),
            )
            non_configuration_permissions = (
                set(instance.user_permissions.all())
                - allowed_configuration_permissions
            )
            new_permissions = non_configuration_permissions.union(
                new_configuration_permissions,
            )
            instance.user_permissions.set(new_permissions)

        # Clear all configuration permissions if an empty list is provided
        if isinstance(permissions_in_payload, list) and len(permissions_in_payload) == 0:
            instance.user_permissions.clear()

        return instance

    def create(self, validated_data):
        password = validated_data.pop("password", None)

        new_configuration_permissions = None
        if (
            "user_permissions" in validated_data
        ):  # This field was renamed from "configuration_permissions" in the meantime
            new_configuration_permissions = set(
                validated_data.pop("user_permissions"),
            )

        user = Dojo_User.objects.create(**validated_data)

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        # This will create only Permissions from category
        # "configuration_permissions". There are no other Permissions.
        if new_configuration_permissions:
            user.user_permissions.set(new_configuration_permissions)

        user.save()
        return user

    def validate(self, data):
        instance_is_superuser = self.instance.is_superuser if self.instance is not None else False
        data_is_superuser = data.get("is_superuser", False)
        if not self.context["request"].user.is_superuser and (
            instance_is_superuser or data_is_superuser
        ):
            msg = "Only superusers are allowed to add or edit superusers."
            raise ValidationError(msg)

        instance_is_staff = self.instance.is_staff if self.instance is not None else False
        data_is_staff = data.get("is_staff", instance_is_staff)
        if not self.context["request"].user.is_superuser and data_is_staff != instance_is_staff:
            msg = "Only superusers are allowed to add or edit staff users."
            raise ValidationError(msg)

        # Configuration permissions are privilege-bearing: they grant the
        # ability to manage users, groups, tool configurations, and so on.
        # Only superusers may assign or change them, which keeps the set of
        # grantable capabilities under superuser control and mirrors the
        # is_staff / is_superuser guards above. The "configuration_permissions"
        # field maps to the "user_permissions" source.
        if "user_permissions" in data and not self.context["request"].user.is_superuser:
            requested_permissions = set(data.get("user_permissions") or [])
            if self.instance is not None:
                allowed_configuration_permissions = set(
                    self.fields["configuration_permissions"].child_relation.queryset.all(),
                )
                current_permissions = (
                    set(self.instance.user_permissions.all())
                    & allowed_configuration_permissions
                )
            else:
                current_permissions = set()
            if requested_permissions != current_permissions:
                msg = "Only superusers are allowed to change configuration permissions."
                raise ValidationError(msg)

        if self.context["request"].method in {"PATCH", "PUT"} and "password" in data:
            msg = "Update of password though API is not allowed"
            raise ValidationError(msg)
        if self.context["request"].method == "POST" and "password" not in data and settings.REQUIRE_PASSWORD_ON_USER:
            msg = "Passwords must be supplied for new users"
            raise ValidationError(msg)
        return super().validate(data)


class UserContactInfoSerializer(serializers.ModelSerializer):
    user_profile = UserSerializer(many=False, source="user", read_only=True)

    class Meta:
        model = UserContactInfo
        # user_state_details is an internal JSON blob for UI state (dismissed
        # banners, "don't show again" flags); keep it out of the public API.
        exclude = ("user_state_details",)

    def validate(self, data):
        user = data.get("user", None) or self.instance.user
        if data.get("force_password_reset", False) and not user.has_usable_password():
            msg = "Password resets are not allowed for users authorized through SSO."
            raise ValidationError(msg)
        return super().validate(data)


class UserStubSerializer(serializers.ModelSerializer):
    class Meta:
        model = Dojo_User
        fields = ("id", "username", "first_name", "last_name")


class AddUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username")


class UserProfileSerializer(serializers.Serializer):
    user = UserSerializer(many=False)
    user_contact_info = UserContactInfoSerializer(many=False, required=False)
