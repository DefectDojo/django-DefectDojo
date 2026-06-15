
from django.conf import settings
from django.db.models import Model
from django.shortcuts import get_object_or_404
from rest_framework import permissions, serializers
from rest_framework.exceptions import (
    ParseError,
    PermissionDenied,
    ValidationError,
)
from rest_framework.request import Request

from dojo.authorization.authorization import (
    user_has_configuration_permission,
    user_has_global_permission,
    user_has_permission,
    user_is_superuser_or_global_owner,
)
from dojo.importers.auto_create_context import AutoCreateContextManager
from dojo.location.models import Location
from dojo.models import (
    Development_Environment,
    Endpoint,
    Engagement,
    Finding,
    Finding_Group,
    Product,
    Product_Type,
    Regulation,
    SLA_Configuration,
    Test,
)


def check_post_permission(request: Request, post_model: Model, post_pk: str | list[str], post_permission: int) -> bool:
    if request.method == "POST":
        if request.data.get(post_pk) is None:
            msg = f"Unable to check for permissions: Attribute '{post_pk}' is required"
            raise ParseError(msg)
        obj = get_object_or_404(post_model, pk=request.data.get(post_pk))
        return user_has_permission(request.user, obj, post_permission)
    return True


def check_object_permission(
    request: Request,
    obj: Model,
    get_permission: int,
    put_permission: int,
    delete_permission: int,
    post_permission: int | None = None,
) -> bool:
    if request.method == "GET":
        return user_has_permission(request.user, obj, get_permission)
    if request.method in {"PUT", "PATCH"}:
        return user_has_permission(request.user, obj, put_permission)
    if request.method == "DELETE":
        return user_has_permission(request.user, obj, delete_permission)
    if request.method == "POST":
        return user_has_permission(request.user, obj, post_permission)
    return False


class BaseRelatedObjectPermission(permissions.BasePermission):

    """
    An "abstract" base class for related object permissions (like notes, metadata, etc.)
    that only need object permissions, not general permissions. This class will serve as
    the base class for other more aptly named permission classes.
    """

    permission_map: dict[str, int] = {
        "get_permission": None,
        "put_permission": None,
        "delete_permission": None,
        "post_permission": None,
    }

    def has_permission(self, request: Request, view):
        # related object only need object permission
        return True

    def has_object_permission(self, request: Request, view, obj):
        return check_object_permission(
            request,
            obj,
            **self.permission_map,
        )


class BaseDjangoModelPermission(permissions.BasePermission):

    """
    An "abstract" base class for Django model permissions.
    This class will serve as the base class for other more aptly named permission classes.
    """

    django_model: Model = None
    request_method_permission_map: dict[str, str] = {
        "GET": "view",
        "POST": "add",
        "PUT": "change",
        "PATCH": "change",
        "DELETE": "delete",
    }

    def _evaluate_permissions(self, request: Request, permissions: dict[str, str]) -> bool:
        # Short circuit if the request method is not in the expected methods
        if request.method not in permissions:
            return True
        # Evaluate the permissions as usual
        for method, permission in permissions.items():
            if request.method == method:
                return user_has_configuration_permission(
                    request.user,
                    f"{self.django_model._meta.app_label}.{permission}_{self.django_model._meta.model_name}",
                )
        return False

    def has_permission(self, request: Request, view):
        # First restrict the mapping got GET/POST only
        expected_request_method_permission_map = {k: v for k, v in self.request_method_permission_map.items() if k in {"GET", "POST"}}
        # Evaluate the permissions
        return self._evaluate_permissions(request, expected_request_method_permission_map)

    def has_object_permission(self, request: Request, view, obj):
        return self._evaluate_permissions(request, self.request_method_permission_map)


class UserHasAppAnalysisPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", "add",
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.product,
            "view",
            "edit",
            "delete",
        )


class UserHasDojoMetaPermission(permissions.BasePermission):
    permission_map = {
        "product": {
            "model": Product,
            "permissions": {
                "get_permission": "view",
                "put_permission": "edit",
                "delete_permission": "edit",
                "post_permission": "edit",
            },
        },
        "finding": {
            "model": Finding,
            "permissions": {
                "get_permission": "view",
                "put_permission": "edit",
                "delete_permission": "edit",
                "post_permission": "edit",
            },
        },
        "location": {
            "model": Location,
            "permissions": {
                "get_permission": "view",
                "put_permission": "edit",
                "delete_permission": "edit",
                "post_permission": "edit",
            },
        },
        # TODO: Delete this after the move to Locations
        "endpoint": {
            "model": Endpoint if not settings.V3_FEATURE_LOCATIONS else Location,
            "permissions": {
                "get_permission": "view",
                "put_permission": "edit",
                "delete_permission": "edit",
                "post_permission": "edit",
            },
        },
    }

    def has_permission(self, request, view):
        method_to_permission_map = {
            "GET": "get_permission",
            "POST": "post_permission",
            # PATCH is generally not used here, but this endpoint is sorta odd...
            "PATCH": "put_permission",
        }
        for request_method, permission_type in method_to_permission_map.items():
            if request.method == request_method:
                has_permission_result = True
                for model_field, schema in self.permission_map.items():
                    if (object_id := request.data.get(model_field)) is not None:
                        obj = get_object_or_404(
                            schema["model"],
                            pk=object_id,
                        )
                        has_permission_result = (
                            has_permission_result
                            and user_has_permission(
                                request.user,
                                obj,
                                schema["permissions"][permission_type],
                            )
                        )
                return has_permission_result
        # If we exit the loop at some point, we must not checking perms for that request method
        return True

    def has_object_permission(self, request, view, obj):
        has_permission_result = True
        for model_field, schema in self.permission_map.items():
            if (object_model := getattr(obj, model_field, None)) is not None:
                has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    object_model,
                    **schema["permissions"],
                )
            )

        return has_permission_result


class UserHasToolProductSettingsPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", "edit",
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.product,
            "view",
            "edit",
            "edit",
        )


# TODO: Delete this after the move to Locations
class UserHasEndpointPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", "add",
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            "view",
            "edit",
            "delete",
        )


# TODO: Delete this after the move to Locations
class UserHasEndpointStatusPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # Check the user can edit both the Endpoint and Finding that the Endpoint_Status will link to
        return (
            check_post_permission(request, Endpoint, "endpoint", "edit")
            and check_post_permission(request, Finding, "finding", "edit")
        )

    def has_object_permission(self, request, view, obj):
        return (
            check_object_permission(
                request,
                obj.endpoint,
                "view",
                "edit",
                "edit",
            )
            and check_object_permission(
                request,
                obj.finding,
                "view",
                "edit",
                "edit",
            )
        )


class UserHasEngagementPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
                request, Product, "product", "add",
            )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            "view",
            "edit",
            "delete",
        )


class UserHasEngagementRelatedObjectPermission(BaseRelatedObjectPermission):
    permission_map = {
        "get_permission": "view",
        "put_permission": "edit",
        "delete_permission": "edit",
        "post_permission": "edit",
    }


class UserHasEngagementNotePermission(BaseRelatedObjectPermission):
    permission_map = {
        "get_permission": "view",
        "put_permission": "edit",
        "delete_permission": "edit",
        "post_permission": "view",
    }


class UserHasRiskAcceptancePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # The previous implementation only checked for the object permission if the path was
        # /api/v2/risk_acceptances/, but the path has always been /api/v2/risk_acceptance/ (notice the missing "s")
        # So there really has not been a notion of a post permission check for risk acceptances.
        # It would be best to leave as is to not break any existing implementations.
        return True

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            "edit",
            "edit",
            "edit",
        )


class UserHasRiskAcceptanceRelatedObjectPermission(BaseRelatedObjectPermission):
    permission_map = {
        "get_permission": "edit",
        "put_permission": "edit",
        "delete_permission": "edit",
        "post_permission": "edit",
    }


class UserHasFindingPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Test, "test", "add",
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            "view",
            "edit",
            "delete",
        )


class UserHasFindingRelatedObjectPermission(BaseRelatedObjectPermission):
    permission_map = {
        "get_permission": "view",
        "put_permission": "edit",
        "delete_permission": "edit",
        "post_permission": "edit",
    }


class UserHasFindingNotePermission(BaseRelatedObjectPermission):
    permission_map = {
        "get_permission": "view",
        "put_permission": "edit",
        "delete_permission": "edit",
        "post_permission": "view",
    }


class UserHasBurpRawRequestResponsePermission(permissions.BasePermission):

    def has_permission(self, request, view):
        return check_post_permission(
            request, Finding, "finding", "add",
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.finding,
            "view",
            "edit",
            "delete",
        )


class UserHasImportPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # permission check takes place before validation, so we don't have access to serializer.validated_data()
        # and we have to validate ourselves unfortunately
        auto_create = AutoCreateContextManager()
        # Process the context to make an conversions needed. Catch any exceptions
        # in this case and wrap them in a DRF exception
        try:
            converted_dict = auto_create.convert_querydict_to_dict(request.data)
            auto_create.process_import_meta_data_from_dict(converted_dict)
            # Get an existing product
            converted_dict["product_type"] = auto_create.get_target_product_type_if_exists(**converted_dict)
            converted_dict["product"] = auto_create.get_target_product_if_exists(**converted_dict)
            converted_dict["engagement"] = auto_create.get_target_engagement_if_exists(**converted_dict)
        except (ValueError, TypeError) as e:
            # Raise an explicit drf exception here
            raise ValidationError(e)
        if engagement := converted_dict.get("engagement"):
            # Validate the resolved engagement's parent chain matches any provided identifiers
            if (product := converted_dict.get("product")) and engagement.product_id != product.id:
                msg = "The provided identifiers are inconsistent — the engagement does not belong to the specified product."
                raise ValidationError(msg)
            if (engagement_name := converted_dict.get("engagement_name")) and engagement.name != engagement_name:
                msg = "The provided identifiers are inconsistent — the engagement name does not match the specified engagement."
                raise ValidationError(msg)
            return user_has_permission(
                request.user, engagement, "import",
            )
        if engagement_id := converted_dict.get("engagement_id"):
            # engagement_id doesn't exist
            msg = f'Engagement "{engagement_id}" does not exist'
            raise serializers.ValidationError(msg)

        if not converted_dict.get("auto_create_context"):
            raise_no_auto_create_import_validation_error(
                None,
                None,
                converted_dict.get("engagement_name"),
                converted_dict.get("product_name"),
                converted_dict.get("product_type_name"),
                converted_dict.get("engagement"),
                converted_dict.get("product"),
                converted_dict.get("product_type"),
                "Need engagement_id or product_name + engagement_name to perform import",
            )
            return None
        # the engagement doesn't exist, so we need to check if the user has
        # requested and is allowed to use auto_create
        return check_auto_create_permission(
            request.user,
            converted_dict.get("product"),
            converted_dict.get("product_name"),
            converted_dict.get("engagement"),
            converted_dict.get("engagement_name"),
            converted_dict.get("product_type"),
            converted_dict.get("product_type_name"),
            "Need engagement_id or product_name + engagement_name to perform import",
        )


class UserHasMetaImportPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # permission check takes place before validation, so we don't have access to serializer.validated_data()
        # and we have to validate ourselves unfortunately
        auto_create = AutoCreateContextManager()
        # Process the context to make an conversions needed. Catch any exceptions
        # in this case and wrap them in a DRF exception
        try:
            converted_dict = auto_create.convert_querydict_to_dict(request.data)
            auto_create.process_import_meta_data_from_dict(converted_dict)
            # Get an existing product
            product = auto_create.get_target_product_if_exists(**converted_dict)
            if not product:
                product = auto_create.get_target_product_by_id_if_exists(**converted_dict)
        except (ValueError, TypeError) as e:
            # Raise an explicit drf exception here
            raise ValidationError(e)

        if product:
            # existing product, nothing special to check
            return user_has_permission(
                request.user, product, "import",
            )
        if product_id := converted_dict.get("product_id"):
            # product_id doesn't exist
            msg = f'Product "{product_id}" does not exist'
            raise serializers.ValidationError(msg)
        msg = "Need product_id or product_name to perform import"
        raise serializers.ValidationError(msg)


class UserHasProductPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request,
            Product_Type,
            "prod_type",
            "add",
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            "view",
            "edit",
            "delete",
        )


class UserHasAssetPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request,
            Product_Type,
            "organization",
            "add",
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            "view",
            "edit",
            "delete",
        )


class UserHasProductTypePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == "POST":
            return user_has_global_permission(
                request.user, "add",
            )
        return True

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            "view",
            "edit",
            "delete",
        )


class UserHasOrganizationPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == "POST":
            return user_has_global_permission(
                request.user, "add",
            )
        return True

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            "view",
            "edit",
            "delete",
        )


class UserHasReimportPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # permission check takes place before validation, so we don't have access to serializer.validated_data()
        # and we have to validate ourselves unfortunately
        auto_create = AutoCreateContextManager()
        # Process the context to make an conversions needed. Catch any exceptions
        # in this case and wrap them in a DRF exception
        try:
            converted_dict = auto_create.convert_querydict_to_dict(request.data)
            auto_create.process_import_meta_data_from_dict(converted_dict)
            # engagement is not a declared field on ReImportScanSerializer and will be
            # stripped during validation — don't use it in the permission check either,
            # so the permission check resolves targets the same way execution does
            converted_dict.pop("engagement", None)
            converted_dict.pop("engagement_id", None)
            # Get an existing product
            converted_dict["product_type"] = auto_create.get_target_product_type_if_exists(**converted_dict)
            converted_dict["product"] = auto_create.get_target_product_if_exists(**converted_dict)
            converted_dict["engagement"] = auto_create.get_target_engagement_if_exists(**converted_dict)
            converted_dict["test"] = auto_create.get_target_test_if_exists(**converted_dict)
        except (ValueError, TypeError) as e:
            # Raise an explicit drf exception here
            raise ValidationError(e)

        if test := converted_dict.get("test"):
            # Validate the resolved test's parent chain matches any provided identifiers
            if (product := converted_dict.get("product")) and test.engagement.product_id != product.id:
                msg = "The provided identifiers are inconsistent — the test does not belong to the specified product."
                raise ValidationError(msg)
            if (engagement := converted_dict.get("engagement")) and test.engagement_id != engagement.id:
                msg = "The provided identifiers are inconsistent — the test does not belong to the specified engagement."
                raise ValidationError(msg)
            # Also validate by name when the objects were not resolved (e.g. names that match no existing record)
            if not converted_dict.get("product") and (product_name := converted_dict.get("product_name")) and test.engagement.product.name != product_name:
                msg = "The provided identifiers are inconsistent — the test does not belong to the specified product."
                raise ValidationError(msg)
            if not converted_dict.get("engagement") and (engagement_name := converted_dict.get("engagement_name")) and test.engagement.name != engagement_name:
                msg = "The provided identifiers are inconsistent — the test does not belong to the specified engagement."
                raise ValidationError(msg)
            return user_has_permission(
                request.user, test, "import",
            )
        if test_id := converted_dict.get("test_id"):
            # test_id doesn't exist
            msg = f'Test "{test_id}" does not exist'
            raise serializers.ValidationError(msg)

        if not converted_dict.get("auto_create_context"):
            raise_no_auto_create_import_validation_error(
                converted_dict.get("test_title"),
                converted_dict.get("scan_type"),
                converted_dict.get("engagement_name"),
                converted_dict.get("product_name"),
                converted_dict.get("product_type_name"),
                converted_dict.get("engagement"),
                converted_dict.get("product"),
                converted_dict.get("product_type"),
                "Need test_id or product_name + engagement_name + scan_type to perform reimport",
            )
            return None
        # the test doesn't exist, so we need to check if the user has
        # requested and is allowed to use auto_create
        return check_auto_create_permission(
            request.user,
            converted_dict.get("product"),
            converted_dict.get("product_name"),
            converted_dict.get("engagement"),
            converted_dict.get("engagement_name"),
            converted_dict.get("product_type"),
            converted_dict.get("product_type_name"),
            "Need test_id or product_name + engagement_name + scan_type to perform reimport",
        )


class UserHasTestPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Engagement, "engagement", "add",
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            "view",
            "edit",
            "delete",
        )


class UserHasTestRelatedObjectPermission(BaseRelatedObjectPermission):
    permission_map = {
        "get_permission": "view",
        "put_permission": "edit",
        "delete_permission": "edit",
        "post_permission": "edit",
    }


class UserHasTestNotePermission(BaseRelatedObjectPermission):
    permission_map = {
        "get_permission": "view",
        "put_permission": "edit",
        "delete_permission": "edit",
        "post_permission": "view",
    }


class UserHasTestImportPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Test, "test", "edit",
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.test,
            "view",
            "edit",
            "delete",
        )


class UserHasLanguagePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", "add",
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            "view",
            "edit",
            "delete",
        )


class UserHasProductAPIScanConfigurationPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request,
            Product,
            "product",
            "add",
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            "view",
            "edit",
            "delete",
        )


class UserHasAssetAPIScanConfigurationPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request,
            Product,
            "asset",
            "add",
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            "view",
            "edit",
            "delete",
        )


class UserHasJiraProductPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == "POST":
            has_permission_result = True
            engagement_id = request.data.get("engagement", None)
            if engagement_id:
                obj = get_object_or_404(Engagement, pk=engagement_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, "edit",
                    )
                )
            product_id = request.data.get("product", None)
            if product_id:
                obj = get_object_or_404(Product, pk=product_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, "edit",
                    )
                )
            return has_permission_result
        return True

    def has_object_permission(self, request, view, obj):
        has_permission_result = True
        engagement = obj.engagement
        if engagement:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    engagement,
                    "view",
                    "edit",
                    "edit",
                )
            )
        product = obj.product
        if product:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    product,
                    "view",
                    "edit",
                    "edit",
                )
            )
        return has_permission_result


class UserHasJiraIssuePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == "POST":
            has_permission_result = True
            engagement_id = request.data.get("engagement", None)
            if engagement_id:
                obj = get_object_or_404(Engagement, pk=engagement_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, "edit",
                    )
                )
            finding_id = request.data.get("finding", None)
            if finding_id:
                obj = get_object_or_404(Finding, pk=finding_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, "edit",
                    )
                )
            finding_group_id = request.data.get("finding_group", None)
            if finding_group_id:
                obj = get_object_or_404(Finding_Group, pk=finding_group_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, "edit",
                    )
                )
            return has_permission_result
        return True

    def has_object_permission(self, request, view, obj):
        has_permission_result = True
        engagement = obj.engagement
        if engagement:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    engagement,
                    "view",
                    "edit",
                    "edit",
                )
            )
        finding = obj.finding
        if finding:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    finding,
                    "view",
                    "edit",
                    "edit",
                )
            )
        finding_group = obj.finding_group
        if finding_group:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    finding_group,
                    "view",
                    "edit",
                    "edit",
                )
            )
        return has_permission_result


class IsSuperUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_superuser


class IsSuperUserOrGlobalOwner(permissions.BasePermission):
    def has_permission(self, request, view):
        return user_is_superuser_or_global_owner(request.user)


class UserHasEngagementPresetPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", "edit",
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.product,
            "view",
            "edit",
            "edit",
            "edit",
        )


class UserHasSLAPermission(BaseDjangoModelPermission):
    django_model = SLA_Configuration


class UserHasDevelopmentEnvironmentPermission(BaseDjangoModelPermission):
    django_model = Development_Environment
    # https://github.com/DefectDojo/django-DefectDojo/blob/963d4a35bfd8f5138330f0d70595a755fa4999b0/dojo/user/utils.py#L93
    # It looks like view permission was explicitly not supported, so I assume
    # reading these endpoints are not necessarily restricted (unless you're auth'd of course)
    request_method_permission_map = {
        "POST": "add",
        "PUT": "change",
        "PATCH": "change",
        "DELETE": "delete",
    }


class UserHasRegulationPermission(BaseDjangoModelPermission):
    django_model = Regulation
    # https://github.com/DefectDojo/django-DefectDojo/blob/963d4a35bfd8f5138330f0d70595a755fa4999b0/dojo/user/utils.py#L104
    # It looks like view permission was explicitly not supported, so I assume
    # reading these endpoints are not necessarily restricted (unless you're auth'd of course)
    request_method_permission_map = {
        "POST": "add",
        "PUT": "change",
        "PATCH": "change",
        "DELETE": "delete",
    }


def raise_no_auto_create_import_validation_error(
    test_title,
    scan_type,
    engagement_name,
    product_name,
    product_type_name,
    engagement,
    product,
    product_type,
    error_message,
):
    # check for mandatory fields first
    if not product_name:
        msg = "product_name parameter missing"
        raise ValidationError(msg)

    if not engagement_name:
        msg = "engagement_name parameter missing"
        raise ValidationError(msg)

    if product_type_name and not product_type:
        msg = f'Product Type "{product_type_name}" does not exist'
        raise serializers.ValidationError(msg)

    if product_name and not product:
        if product_type_name:
            msg = f'Product "{product_name}" does not exist in Product_Type "{product_type_name}"'
            raise serializers.ValidationError(msg)
        msg = f'Product "{product_name}" does not exist'
        raise serializers.ValidationError(msg)

    if engagement_name and not engagement:
        msg = f'Engagement "{engagement_name}" does not exist in Product "{product_name}"'
        raise serializers.ValidationError(msg)

    # these are only set for reimport
    if test_title:
        msg = f'Test "{test_title}" with scan_type "{scan_type}" does not exist in Engagement "{engagement_name}"'
        raise serializers.ValidationError(msg)

    if scan_type:
        msg = f'Test with scan_type "{scan_type}" does not exist in Engagement "{engagement_name}"'
        raise serializers.ValidationError(msg)

    raise ValidationError(error_message)


def check_auto_create_permission(
    user,
    product,
    product_name,
    engagement,
    engagement_name,
    product_type,
    product_type_name,
    error_message,
):
    """
    For an existing engagement, to be allowed to import a scan, the following must all be True:
    - User must have Import_Scan_Result permission for this Engagement

    For an existing product, to be allowed to import into a new engagement with name `engagement_name`, the following must all be True:
    - Product with name `product_name`  must already exist;
    - User must have Engagement_Add permission for this Product
    - User must have Import_Scan_Result permission for this Product

    If the product doesn't exist yet, to be allowed to import into a new product with name `product_name` and prod_type `product_type_name`,
    the following must all be True:
    - `auto_create_context` must be True
    - Product_Type already exists, or the user has the Product_Type_Add permission
    - User must have Product_Type_Add_Product permission for the Product_Type, or the user has the Product_Type_Add permission
    """
    if not product_name:
        msg = "product_name parameter missing"
        raise ValidationError(msg)

    if not engagement_name:
        msg = "engagement_name parameter missing"
        raise ValidationError(msg)

    if engagement:
        # Validate the resolved engagement's parent chain matches any provided names
        if product is not None and engagement.product_id != product.id:
            msg = "The provided identifiers are inconsistent — the engagement does not belong to the specified product."
            raise ValidationError(msg)
        return user_has_permission(
            user, engagement, "import",
        )

    if product and product_name and engagement_name:
        if not user_has_permission(user, product, "add"):
            msg = f'No permission to create engagements in product "{product_name}"'
            raise PermissionDenied(msg)

        if not user_has_permission(
            user, product, "import",
        ):
            msg = f'No permission to import scans into product "{product_name}"'
            raise PermissionDenied(msg)

        # all good
        return True

    if not product and product_name:
        if not product_type_name:
            msg = f'Product "{product_name}" does not exist and no product_type_name provided to create the new product in'
            raise serializers.ValidationError(msg)

        if not product_type:
            if not user_has_global_permission(
                user, "add",
            ):
                msg = f'No permission to create product_type "{product_type_name}"'
                raise PermissionDenied(msg)
            # new product type can be created with current user as owner, so
            # all objects in it can be created as well
            return True
        if not user_has_permission(
            user, product_type, "add",
        ):
            msg = f'No permission to create products in product_type "{product_type}"'
            raise PermissionDenied(msg)

        # product can be created, so objects in it can be created as well
        return True

    raise ValidationError(error_message)


class UserHasConfigurationPermissionStaff(permissions.DjangoModelPermissions):
    # Override map to also provide 'view' permissions
    perms_map = {
        "GET": ["%(app_label)s.view_%(model_name)s"],
        "OPTIONS": [],
        "HEAD": [],
        "POST": ["%(app_label)s.add_%(model_name)s"],
        "PUT": ["%(app_label)s.change_%(model_name)s"],
        "PATCH": ["%(app_label)s.change_%(model_name)s"],
        "DELETE": ["%(app_label)s.delete_%(model_name)s"],
    }

    def has_permission(self, request, view):
        return super().has_permission(request, view)


class UserHasConfigurationPermissionSuperuser(
    permissions.DjangoModelPermissions,
):
    # Override map to also provide 'view' permissions
    perms_map = {
        "GET": ["%(app_label)s.view_%(model_name)s"],
        "OPTIONS": [],
        "HEAD": [],
        "POST": ["%(app_label)s.add_%(model_name)s"],
        "PUT": ["%(app_label)s.change_%(model_name)s"],
        "PATCH": ["%(app_label)s.change_%(model_name)s"],
        "DELETE": ["%(app_label)s.delete_%(model_name)s"],
    }

    def has_permission(self, request, view):
        return super().has_permission(request, view)


class LocationFindingReferencePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request,
            Finding,
            "finding",
            "edit",
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.finding,
            "view",
            "edit",
            "edit",
        )


class LocationProductReferencePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request,
            Product,
            "product",
            "edit",
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.product,
            "view",
            "edit",
            "edit",
        )
