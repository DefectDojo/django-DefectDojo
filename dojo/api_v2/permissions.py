import re
from django.shortcuts import get_object_or_404
from rest_framework import permissions, serializers
from rest_framework.exceptions import (
    ParseError,
    PermissionDenied,
    ValidationError,
)

from dojo.authorization.authorization import (
    user_has_configuration_permission,
    user_has_global_permission,
    user_has_permission,
    user_has_role_permission,
)
from dojo.api_v2.api_error import ApiError
from dojo.group.queries import get_users_for_group, get_users_for_group_by_role
from dojo.authorization.roles_permissions import Permissions
from dojo.templatetags.authorization_tags import is_in_group
from dojo.importers.auto_create_context import AutoCreateContextManager
from dojo.engine_tools.helpers import Constants
from dojo.api_v2.long_risk_acceptance.models import RiskAcceptanceEngagement, RiskAcceptanceEngagementEconomicImpact
from dojo.models import (
    Cred_Mapping,
    Dojo_Group,
    Endpoint,
    Engagement,
    Finding,
    Finding_Group,
    Product,
    Product_Type,
    Test,
    GeneralSettings,
    Risk_Acceptance,
    Input,
    TransferFinding,
    TransferFindingFinding
)

def check_field_permissions(request, post_model, post_pk):
    """ Check if user has permission to edit specific fields based on their role group. """

    FIELD_PERMISSIONS = {
        "Risk": {f"expiration_date": Permissions.Risk_Acceptance_Expire_Date_Edit},
        "Developer": {},
        "Leader": {},
    }
    # validation by group security
    role_group = "Risk"
    users = get_users_for_group_by_role(
        GeneralSettings.get_value("GROUP_APPROVERS_LONGTERM_ACCEPTANCE", "Approvers_risk"),
        role_group
    )
    field_request = request.data.keys()
    if request.user in users:
        allowed_fields = FIELD_PERMISSIONS.get(role_group, [])
        if not allowed_fields or not field_request:
            return False
        for field in field_request:
            if field not in allowed_fields.keys():
                raise ApiError.precondition_failed(
                    detail=f"User does not have permission to edit field: {field}"
                )
        return True
    return False


def check_patch_permission(request, post_model, patch_pk, patch_permission):
    if patch_pk is None:
        msg = f"Unable to check for permissions: Parameters '{patch_pk}' is required"
        raise ParseError(msg)
    obj = get_object_or_404(post_model, pk=patch_pk)
    return user_has_permission(request.user, obj, patch_permission)


def check_post_permission(request, post_model, post_pk, post_permission):
    if request.method == "POST":
        obj_id = request.data.get(post_pk) or request.query_params.get(post_pk)
        if obj_id is None:
            msg = f"Unable to check for permissions: Attribute '{post_pk}' is required"
            raise ParseError(msg)
        if isinstance(obj_id, list) and len(obj_id) > 0:
            obj_id = obj_id[0]
        obj = get_object_or_404(post_model, pk=obj_id)
        return user_has_permission(request.user, obj, post_permission)
    return True



def check_object_permission(
    request,
    obj,
    get_permission,
    put_permission,
    delete_permission,
    post_permission=None,
):

    if request.method == "GET":
        return user_has_permission(request.user, obj, get_permission)
    if request.method in {"PUT", "PATCH"}:
        return user_has_permission(request.user, obj, put_permission)
    if request.method == "DELETE":
        return user_has_permission(request.user, obj, delete_permission)
    if request.method == "POST":
        return user_has_permission(request.user, obj, post_permission)
    return False


class UserHasAppAnalysisPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", Permissions.Technology_Add,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.product,
            Permissions.Technology_View,
            Permissions.Technology_Edit,
            Permissions.Technology_Delete,
        )


class UserHasCredentialPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.data.get("product") is not None:
            return check_post_permission(
                request, Cred_Mapping, "product", Permissions.Credential_Add,
            )
        if request.data.get("engagement") is not None:
            return check_post_permission(
                request, Cred_Mapping, "engagement", Permissions.Credential_Add,
            )
        if request.data.get("test") is not None:
            return check_post_permission(
                request, Cred_Mapping, "test", Permissions.Credential_Add,
            )
        if request.data.get("finding") is not None:
            return check_post_permission(
                request, Cred_Mapping, "finding", Permissions.Credential_Add,
            )
        return check_post_permission(
            request, Cred_Mapping, "product", Permissions.Credential_Add,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.product,
            Permissions.Credential_View,
            Permissions.Credential_Edit,
            Permissions.Credential_Delete,
        )


class UserHasDojoGroupPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == "GET":
            if request.query_params.get("name") in GeneralSettings.get_value("GROUP_USER_PERMISSION_VIEW", ["Approvers_Risk"]) or request.query_params.get("id") in GeneralSettings.get_value("GROUP_USER_PERMISSION_VIEW", ["Approvers_Risk"]):
                return True
            else:
                return user_has_configuration_permission(
                    request.user, "auth.view_group",
                )
        if request.method == "POST":
            return user_has_configuration_permission(
                request.user, "auth.add_group",
            )
        return True

    def has_object_permission(self, request, view, obj):
        if request.method == "GET":
            # Users need to be authorized to view groups in general and only the groups they are a member of
            # because with the group they can see user information that might
            # be considered as confidential
            return user_has_configuration_permission(
                request.user, "auth.view_group",
            ) and user_has_permission(
                request.user, obj, Permissions.Group_View,
            )
        return check_object_permission(
            request,
            obj,
            Permissions.Group_View,
            Permissions.Group_Edit,
            Permissions.Group_Delete,
        )


class UserHasDojoGroupMemberPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Dojo_Group, "group", Permissions.Group_Manage_Members,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Group_View,
            Permissions.Group_Manage_Members,
            Permissions.Group_Member_Delete,
        )


class UserHasDojoMetaPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == "POST":
            has_permission_result = True
            product_id = request.data.get("product", None)
            if product_id:
                obj = get_object_or_404(Product, pk=product_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, Permissions.Product_Edit,
                    )
                )
            finding_id = request.data.get("finding", None)
            if finding_id:
                obj = get_object_or_404(Finding, pk=finding_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, Permissions.Finding_Edit,
                    )
                )
            endpoint_id = request.data.get("endpoint", None)
            if endpoint_id:
                obj = get_object_or_404(Endpoint, pk=endpoint_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, Permissions.Endpoint_Edit,
                    )
                )
            return has_permission_result
        return True

    def has_object_permission(self, request, view, obj):
        has_permission_result = True
        product = obj.product
        if product:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    product,
                    Permissions.Product_View,
                    Permissions.Product_Edit,
                    Permissions.Product_Edit,
                )
            )
        finding = obj.finding
        if finding:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    finding,
                    Permissions.Finding_View,
                    Permissions.Finding_Edit,
                    Permissions.Finding_Edit,
                )
            )
        endpoint = obj.endpoint
        if endpoint:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    endpoint,
                    Permissions.Endpoint_View,
                    Permissions.Endpoint_Edit,
                    Permissions.Endpoint_Edit,
                )
            )
        return has_permission_result


class UserHasToolProductSettingsPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", Permissions.Product_Edit,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.product,
            Permissions.Product_View,
            Permissions.Product_Edit,
            Permissions.Product_Edit,
        )

class UserHasComponentPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Engagement, "engagement_id", Permissions.Component_Add,
        )
    
    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Component_View,
            Permissions.Component_Edit,
            Permissions.Component_Delete,
        )

class UserHasEndpointPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", Permissions.Endpoint_Add,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Endpoint_View,
            Permissions.Endpoint_Edit,
            Permissions.Endpoint_Delete,
        )


class UserHasEndpointStatusPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Endpoint, "endpoint", Permissions.Endpoint_Edit,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.endpoint,
            Permissions.Endpoint_View,
            Permissions.Endpoint_Edit,
            Permissions.Endpoint_Edit,
        )


class UserHasEngagementPermission(permissions.BasePermission):
    # Permission checks for related objects (like notes or metadata) can be moved
    # into a seperate class, when the legacy authorization will be removed.
    path_engagement_post = re.compile(r"^/api/v2/engagements/$")
    path_engagement = re.compile(r"^/api/v2/engagements/\d+/$")

    def has_permission(self, request, view):
        if UserHasEngagementPermission.path_engagement_post.match(
            request.path,
        ) or UserHasEngagementPermission.path_engagement.match(request.path):
            return check_post_permission(
                request, Product, "product", Permissions.Engagement_Add,
            )
        # related object only need object permission
        return True

    def has_object_permission(self, request, view, obj):
        if UserHasEngagementPermission.path_engagement_post.match(
            request.path,
        )   or UserHasEngagementPermission.path_engagement.match(request.path):
            return check_object_permission(
                request,
                obj,
                Permissions.Engagement_View,
                Permissions.Engagement_Edit,
                Permissions.Engagement_Delete,
            )
        return check_object_permission(
            request,
            obj,
            Permissions.Engagement_View,
            Permissions.Engagement_Edit,
            Permissions.Engagement_Edit,
            Permissions.Engagement_Edit,
        )


class UserHasRiskAcceptancePermission(permissions.BasePermission):
    # Permission checks for related objects (like notes or metadata) can be moved
    # into a seperate class, when the legacy authorization will be removed.
    path_risk_acceptance_post = re.compile(r"^/api/v2/risk_acceptances/$")
    path_risk_acceptance = re.compile(r"^/api/v2/risk_acceptance/\d+/$")
    path_risk_acceptance_bulk = re.compile(r"^/api/v2/risk_acceptance/\d+/accept_bulk/$")

   

    def has_permission(self, request, view):
        risk_acceptance_id = view.kwargs.get("pk", None) 

        if UserHasRiskAcceptancePermission.path_risk_acceptance_bulk.match(request.path):
            return user_has_global_permission(request.user, Permissions.Risk_Acceptance_Bulk) 
        if UserHasRiskAcceptancePermission.path_risk_acceptance_post.match(
            request.path,
        ) or UserHasRiskAcceptancePermission.path_risk_acceptance.match(
            request.path,
        ):
            if request.method in ["PATCH", "PUT"]:
                if check_patch_permission(request, Risk_Acceptance, risk_acceptance_id, Permissions.Risk_Acceptance_Edit) is True:
                    return True
                else:
                    return check_field_permissions(request, Risk_Acceptance, "risk_acceptance")
            else:
                return check_post_permission(
                    request, Product, "product", Permissions.Risk_Acceptance,
                )
        return True

    def has_object_permission(self, request, view, obj):
        if UserHasRiskAcceptancePermission.path_risk_acceptance_post.match(
            request.path,
        ) or UserHasRiskAcceptancePermission.path_risk_acceptance.match(
            request.path,
        ):
            return check_object_permission(
                request,
                obj,
                Permissions.Risk_Acceptance,
                Permissions.Risk_Acceptance,
                Permissions.Risk_Acceptance,
            )
        return check_object_permission(
            request,
            obj,
            Permissions.Risk_Acceptance,
            Permissions.Risk_Acceptance,
            Permissions.Risk_Acceptance,
            Permissions.Risk_Acceptance,
        )


class UserHasFindingPermission(permissions.BasePermission):
    # Permission checks for related objects (like notes or metadata) can be moved
    # into a seperate class, when the legacy authorization will be removed.
    path_finding_post = re.compile(r"^/api/v2/findings/$")
    path_finding = re.compile(r"^/api/v2/findings/\d+/$")
    path_stub_finding_post = re.compile(r"^/api/v2/stub_findings/$")
    path_stub_finding = re.compile(r"^/api/v2/stub_findings/\d+/$")
    path_finding_bulk_close = re.compile(r"^/api/v2/findings/bulk_close/$")

    def has_permission(self, request, view):
        if UserHasFindingPermission. \
                path_finding_bulk_close.match(request.path):
            return user_has_global_permission(
                request.user,
                permission=Permissions.Finding_Bulk_Close)
        if (
            UserHasFindingPermission.path_finding_post.match(request.path)
            or UserHasFindingPermission.path_finding.match(request.path)
            or UserHasFindingPermission.path_stub_finding_post.match(
                request.path,
            )
            or UserHasFindingPermission.path_stub_finding.match(request.path)
        ):
            return check_post_permission(
                request, Test, "test", Permissions.Finding_Add,
            )
        # related object only need object permission
        return True

    def has_object_permission(self, request, view, obj):
        if (
            UserHasFindingPermission.path_finding_post.match(request.path)
            or UserHasFindingPermission.path_finding.match(request.path)
            or UserHasFindingPermission.path_stub_finding_post.match(
                request.path,
            )
            or UserHasFindingPermission.path_stub_finding.match(request.path)
        ):
            return check_object_permission(
                request,
                obj,
                Permissions.Finding_View,
                Permissions.Finding_Edit,
                Permissions.Finding_Delete,
            )
        return check_object_permission(
            request,
            obj,
            Permissions.Finding_View,
            Permissions.Finding_Edit,
            Permissions.Finding_Edit,
            Permissions.Finding_Edit,
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
            # existing engagement, nothing special to check
            return user_has_permission(
                request.user, engagement, Permissions.Import_Scan_Result,
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
                request.user, product, Permissions.Import_Scan_Result,
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
            Permissions.Product_Type_Add_Product,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Product_View,
            Permissions.Product_Edit,
            Permissions.Product_Delete,
        )


class UserHasProductMemberPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", Permissions.Product_Manage_Members,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Product_View,
            Permissions.Product_Manage_Members,
            Permissions.Product_Member_Delete,
        )


class UserHasProductGroupPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", Permissions.Product_Group_Add,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Product_Group_View,
            Permissions.Product_Group_Edit,
            Permissions.Product_Group_Delete,
        )


class UserHasProductTypePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == "POST":
            return user_has_global_permission(
                request.user, Permissions.Product_Type_Add,
            )
        return True

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Product_Type_View,
            Permissions.Product_Type_Edit,
            Permissions.Product_Type_Delete,
        )


class UserHasProductTypeMemberPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request,
            Product_Type,
            "product_type",
            Permissions.Product_Type_Manage_Members,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Product_Type_View,
            Permissions.Product_Type_Manage_Members,
            Permissions.Product_Type_Member_Delete,
        )


class UserHasProductTypeGroupPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request,
            Product_Type,
            "product_type",
            Permissions.Product_Type_Group_Add,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Product_Type_Group_View,
            Permissions.Product_Type_Group_Edit,
            Permissions.Product_Type_Group_Delete,
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
            # Get an existing product
            converted_dict["product_type"] = auto_create.get_target_product_type_if_exists(**converted_dict)
            converted_dict["product"] = auto_create.get_target_product_if_exists(**converted_dict)
            converted_dict["engagement"] = auto_create.get_target_engagement_if_exists(**converted_dict)
            converted_dict["test"] = auto_create.get_target_test_if_exists(**converted_dict)
        except (ValueError, TypeError) as e:
            # Raise an explicit drf exception here
            raise ValidationError(e)

        if test := converted_dict.get("test"):
            # existing test, nothing special to check
            return user_has_permission(
                request.user, test, Permissions.Import_Scan_Result,
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
    # Permission checks for related objects (like notes or metadata) can be moved
    # into a seperate class, when the legacy authorization will be removed.
    path_tests_post = re.compile(r"^/api/v2/tests/$")
    path_tests = re.compile(r"^/api/v2/tests/\d+/$")

    def has_permission(self, request, view):
        if UserHasTestPermission.path_tests_post.match(
            request.path,
        ) or UserHasTestPermission.path_tests.match(request.path):
            return check_post_permission(
                request, Engagement, "engagement", Permissions.Test_Add,
            )
        # related object only need object permission
        return True

    def has_object_permission(self, request, view, obj):
        if UserHasTestPermission.path_tests_post.match(
            request.path,
        ) or UserHasTestPermission.path_tests.match(request.path):
            return check_object_permission(
                request,
                obj,
                Permissions.Test_View,
                Permissions.Test_Edit,
                Permissions.Test_Delete,
            )
        return check_object_permission(
            request,
            obj,
            Permissions.Test_View,
            Permissions.Test_Edit,
            Permissions.Test_Edit,
            Permissions.Test_Edit,
        )


class UserHasTestImportPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Test, "test", Permissions.Test_Edit,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.test,
            Permissions.Test_View,
            Permissions.Test_Edit,
            Permissions.Test_Delete,
        )


class UserHasLanguagePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", Permissions.Language_Add,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Language_View,
            Permissions.Language_Edit,
            Permissions.Language_Delete,
        )


class UserHasProductAPIScanConfigurationPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request,
            Product,
            "product",
            Permissions.Product_API_Scan_Configuration_Add,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj,
            Permissions.Product_API_Scan_Configuration_View,
            Permissions.Product_API_Scan_Configuration_Edit,
            Permissions.Product_API_Scan_Configuration_Delete,
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
                        request.user, obj, Permissions.Engagement_Edit,
                    )
                )
            product_id = request.data.get("product", None)
            if product_id:
                obj = get_object_or_404(Product, pk=product_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, Permissions.Product_Edit,
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
                    Permissions.Engagement_View,
                    Permissions.Engagement_Edit,
                    Permissions.Engagement_Edit,
                )
            )
        product = obj.product
        if product:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    product,
                    Permissions.Product_View,
                    Permissions.Product_Edit,
                    Permissions.Product_Edit,
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
                        request.user, obj, Permissions.Engagement_Edit,
                    )
                )
            finding_id = request.data.get("finding", None)
            if finding_id:
                obj = get_object_or_404(Finding, pk=finding_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, Permissions.Finding_Edit,
                    )
                )
            finding_group_id = request.data.get("finding_group", None)
            if finding_group_id:
                obj = get_object_or_404(Finding_Group, pk=finding_group_id)
                has_permission_result = (
                    has_permission_result
                    and user_has_permission(
                        request.user, obj, Permissions.Finding_Group_Edit,
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
                    Permissions.Engagement_View,
                    Permissions.Engagement_Edit,
                    Permissions.Engagement_Edit,
                )
            )
        finding = obj.finding
        if finding:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    finding,
                    Permissions.Finding_View,
                    Permissions.Finding_Edit,
                    Permissions.Finding_Edit,
                )
            )
        finding_group = obj.finding_group
        if finding_group:
            has_permission_result = (
                has_permission_result
                and check_object_permission(
                    request,
                    finding_group,
                    Permissions.Finding_Group_View,
                    Permissions.Finding_Group_Edit,
                    Permissions.Finding_Group_Edit,
                )
            )
        return has_permission_result


class IsSuperUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_superuser


class UserHasEngagementPresetPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(
            request, Product, "product", Permissions.Product_Edit,
        )

    def has_object_permission(self, request, view, obj):
        return check_object_permission(
            request,
            obj.product,
            Permissions.Product_View,
            Permissions.Product_Edit,
            Permissions.Product_Edit,
            Permissions.Product_Edit,
        )


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
        # existing engagement, nothing special to check
        return user_has_permission(
            user, engagement, Permissions.Import_Scan_Result,
        )

    if product and product_name and engagement_name:
        if not user_has_permission(user, product, Permissions.Engagement_Add):
            msg = f'No permission to create engagements in product "{product_name}"'
            raise PermissionDenied(msg)

        if not user_has_permission(
            user, product, Permissions.Import_Scan_Result,
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
                user, Permissions.Product_Type_Add,
            ):
                msg = f'No permission to create product_type "{product_type_name}"'
                raise PermissionDenied(msg)
            # new product type can be created with current user as owner, so
            # all objects in it can be created as well
            return True
        if not user_has_permission(
            user, product_type, Permissions.Product_Type_Add_Product,
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


class UserHasViewSwaggerDocumentation(permissions.BasePermission):

    def has_permission(self, request, view):
        return user_has_global_permission(
            request.user, Permissions.Swagger_Documentation
        )


class UserHasViewApiV2Key(permissions.BasePermission):

    def has_permission(self, request, view):
        return user_has_global_permission(
            request.user, Permissions.Api_v2_Key
        )


class IsAPIImporter(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_superuser:
            return True
        if hasattr(request.user, 'global_role'):
            if request.user.global_role:
                if request.user.global_role.role.name in ["API_Importer", "Maintainer"]:
                    return True
        return False


class UserHasPermissionGeneralSettings(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_superuser:
            return True

        if hasattr(request.user, 'global_role'):
            if request.user.global_role:
                return user_has_global_permission(
                    request.user,
                    Permissions.General_Settings_Add,
)    
        return False


class UserHasPermissionManagerCache(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_superuser:
            return True

        if hasattr(request.user, 'global_role'):
            if request.user.global_role:
                return user_has_global_permission(
                    request.user,
                    Permissions.General_Settings_Add,)
        return False


class UserHasPermissionMetricsIA(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_superuser:
            return True

        if hasattr(request.user, 'global_role'):
            if request.user.global_role:
                return user_has_global_permission(
                    request.user,
                    Permissions.Ia_Metrics,)
        return False

class UserHasPermissionMetricsPanel(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_superuser:
            return True

        if hasattr(request.user, 'global_role'):
            if request.user.global_role:
                return user_has_global_permission(
                    request.user,
                    Permissions.Metrics_Panel_Admin,)
        return False

class UserHasPermissionSendEmail(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_superuser:
            return True

        if hasattr(request.user, 'global_role'):
            if request.user.global_role:
                return user_has_global_permission(
                    request.user,
                    Permissions.Risk_Acceptance_Send_Email,)
        return False


class UserHasInputPermission(permissions.BasePermission):
    # Permission checks for related objects (like notes or metadata) can be moved
    # into a seperate class, when the legacy authorization will be removed.
    path_input_post = re.compile(r"^/api/v2/scope/$")
    path_input = re.compile(r"^/api/v2/scope/\d+/$")
    path_input_post_secret = re.compile(r"^/api/v2/scope/create_scope_secret/$")
    path_input_post_file = re.compile(r"^/api/v2/scope/create_scope_file/$")

    def has_permission(self, request, view):
        if (
            UserHasInputPermission.path_input_post.match(request.path,) or
            UserHasInputPermission.path_input.match(request.path) or
            UserHasInputPermission.path_input_post_secret.match(request.path) or
            UserHasInputPermission.path_input_post_file.match(request.path)
        ):
            return check_post_permission(
                request, Product, "product", Permissions.Product_View,
            )
        # related object only need object permission
        return True

    def has_object_permission(self, request, view, obj):
        if UserHasInputPermission.path_input_post.match(
            request.path,
        ) or UserHasInputPermission.path_input.match(request.path):
            return check_object_permission(
                request,
                obj,
                Permissions.Input_View,
                Permissions.Input_Edit,
                Permissions.Input_Delete,
            )
        return check_object_permission(
            request,
            obj,
            Permissions.Input_View,
            Permissions.Input_Edit,
            Permissions.Input_Edit,
            Permissions.Input_Edit,
        )

class UserHasLongRiskAcceptancePermission(permissions.BasePermission):
    # Permission checks for related objects (like notes or metadata) can be moved
    # into a seperate class, when the legacy authorization will be removed.
    path_post = re.compile(r"^/api/v2/long_risk_acceptance/$")
    path = re.compile(r"^/api/v2/long_risk_acceptance/\d+/$")
    path_apply_rule = re.compile(r"^/api/v2/long_risk_acceptance/apply_rule/\d+/$")
    path_notes = re.compile(r"^/api/v2/long_risk_acceptance/\d+/notes/$")

    def has_permission(self, request, view):
        if UserHasLongRiskAcceptancePermission.path_post.match(
            request.path,
        ) or UserHasLongRiskAcceptancePermission.path.match(request.path):
            return check_post_permission(
                request, Product, "product", Permissions.Product_View,
            ) 
        # related object only need object permission
        return True

    def has_object_permission(self, request, view, obj):
        if UserHasLongRiskAcceptancePermission.path_post.match(
            request.path,
        ) or UserHasLongRiskAcceptancePermission.path.match(request.path):
            return check_object_permission(
                request,
                obj,
                Permissions.Long_Risk_Acceptance_Eng_View,
                Permissions.Long_Risk_Acceptance_Eng_Edit,
                Permissions.Long_Risk_Acceptance_Eng_Delete,
            )
        elif UserHasLongRiskAcceptancePermission.path_apply_rule.match(
            request.path,
        ):
            return check_object_permission(
                request,
                obj,
                Permissions.Risk_Acceptance_Eng_Reject,
            )
        elif UserHasLongRiskAcceptancePermission.path_notes.match(
            request.path,
        ):
            return check_object_permission(
                request,
                obj,
                Permissions.Long_Risk_Acceptance_Eng_View,
                Permissions.Risk_Acceptance_Eng_Note_Edit,
                Permissions.Risk_Acceptance_Eng_Note_Delete,
                Permissions.Risk_Acceptance_Eng_Note_Add,
            )

        return check_object_permission(
            request,
            obj,
            Permissions.Long_Risk_Acceptance_Eng_View,
            Permissions.Long_Risk_Acceptance_Eng_Edit,
            Permissions.Long_Risk_Acceptance_Eng_Delete,
            Permissions.Risk_Acceptance_Eng_Reject,
        )

class UserHasLongRiskAcceptanceRulePermission(permissions.BasePermission):
    # Permission checks for related objects (like notes or metadata) can be moved
    # into a seperate class, when the legacy authorization will be removed.
    path_post = re.compile(r"^/api/v2/long_risk_acceptance_rule/$")
    path = re.compile(r"^/api/v2/long_risk_acceptance_rule/\d+/$")

    def has_permission(self, request, view):
        if UserHasLongRiskAcceptanceRulePermission.path_post.match(
            request.path,
        ) or UserHasLongRiskAcceptanceRulePermission.path.match(request.path):
            return check_post_permission(
                request, RiskAcceptanceEngagement, "ra_engagement", Permissions.Long_Risk_Acceptance_Eng_View,
            )
        # related object only need object permission
        return True

    def has_object_permission(self, request, view, obj):
        if UserHasLongRiskAcceptancePermission.path_post.match(
            request.path,
        ) or UserHasLongRiskAcceptancePermission.path.match(request.path):
            return check_object_permission(
                request,
                obj,
                Permissions.Long_Risk_Acceptance_Rule_Eng_View,
                Permissions.Long_Risk_Acceptance_Rule_Eng_Edit,
                Permissions.Long_Risk_Acceptance_Rule_Eng_Delete,
            )
        return check_object_permission(
            request,
            obj,
            Permissions.Long_Risk_Acceptance_Rule_Eng_View,
            Permissions.Long_Risk_Acceptance_Rule_Eng_Edit,
            Permissions.Long_Risk_Acceptance_Rule_Eng_Delete,
        )

class UserHasImpactEconomicPermission(permissions.BasePermission):
    path_post = re.compile(r"^/api/v2/economic_impact/$")
    path = re.compile(r"^/api/v2/economic_impact/\d+/$")

    def has_permission(self, request, view):
        if UserHasImpactEconomicPermission.path_post.match(request.path):
            return user_has_role_permission(
                request.user, Permissions.Long_Risk_Acceptance_Impact_Economic_Add,
            )
        # related object only need object permission
        return True

    def has_object_permission(self, request, view, obj):
        if UserHasImpactEconomicPermission.path_post.match(
            request.path,
        ) or UserHasImpactEconomicPermission.path.match(request.path):
            return check_object_permission(
                request,
                obj,
                Permissions.Long_Risk_Acceptance_Impact_Economic_View,
                Permissions.Long_Risk_Acceptance_Impact_Economic_Edit,
                Permissions.Long_Risk_Acceptance_Impact_Economic_Delete,
                Permissions.Long_Risk_Acceptance_Impact_Economic_Add,
            )
        return check_object_permission(
            request,
            obj,
            Permissions.Long_Risk_Acceptance_Impact_Economic_View,
            Permissions.Long_Risk_Acceptance_Impact_Economic_Edit,
            Permissions.Long_Risk_Acceptance_Impact_Economic_Delete,
            Permissions.Long_Risk_Acceptance_Impact_Economic_Add,
        )

class UserHasTransferFindingFindingPermission(permissions.BasePermission):
    path_transfer_finding_finding_post = re.compile(r"^/api/v2/transfer_finding_findings/$")
    path_transfer_finding_finding = re.compile(r"^/api/v2/transfer_finding_findings/\d+/$")
    path_transfer_finding_finding_change_status = re.compile(r"^/api/v2/transfer_finding_findings/\d+/change_status/$")
    path_transfer_finding_finding_pre_review = re.compile(r"^/api/v2/transfer_finding_findings/\d+/pre_review/$")

    def has_permission(self, request, view):
        transfer_finding_id = view.kwargs.get("pk", None)
        if self.path_transfer_finding_finding_post.match(request.path):
            return check_post_permission(
                request, Finding, "findings", Permissions.Transfer_Finding_Finding_Add,
            )
        if self.path_transfer_finding_finding_change_status.match(request.path):
            return check_patch_permission(request, TransferFinding, transfer_finding_id, Permissions.Transfer_Finding_Finding_Accept)
        if self.path_transfer_finding_finding.match(
            request.path,
        ):
            if request.method in ["PATCH", "PUT"]:
                return check_patch_permission(request, TransferFinding, transfer_finding_id, Permissions.Transfer_Finding_Finding_Edit)
        if self.path_transfer_finding_finding_pre_review.match(request.path):
            obj = get_object_or_404(TransferFindingFinding, pk=transfer_finding_id)
            return check_object_permission(
                request,
                obj,
                Permissions.Transfer_Finding_Finding_View,
                Permissions.Transfer_Finding_Finding_Edit,
                Permissions.Transfer_Finding_Finding_Delete,
                Permissions.Transfer_Finding_Finding_Add,
            )

        return True 

    def has_object_permission(self, request, view, obj):
        if (
            self.path_transfer_finding_finding_post.match(
                request.path,
            ) or self.path_transfer_finding_finding.match(
                request.path
            )
            ):
            return check_object_permission(
                request,
                obj,
                Permissions.Transfer_Finding_Finding_View,
                Permissions.Transfer_Finding_Finding_Edit,
                Permissions.Transfer_Finding_Finding_Delete,
            )
        return check_object_permission(
            request,
            obj,
            Permissions.Transfer_Finding_Finding_View,
            Permissions.Transfer_Finding_Finding_Edit,
            Permissions.Transfer_Finding_Finding_Delete,
            Permissions.Transfer_Finding_Finding_Accept,
        )
    
class UserHasTransferFindingPermission(permissions.BasePermission):
    path_transfer_finding_post = re.compile(r"^/api/v2/transfer_finding/$")
    path_transfer_finding_patch = re.compile(r"^/api/v2/transfer_finding/\d+/$")

    def has_permission(self, request, view):
        transfer_finding_id = view.kwargs.get("pk", None)

        if self.path_transfer_finding_patch.match(request.path):
            if request.method in ["PATCH", "PUT"]:
                return check_patch_permission(request, TransferFinding, transfer_finding_id, Permissions.Transfer_Finding_Edit)

        return True


    def has_object_permission(self, request, view, obj):
        if (
            self.path_transfer_finding_post.match(request.path)
            or self.path_transfer_finding_patch.match(request.path)
        ):
            return check_object_permission(
                request,
                obj,
                Permissions.Transfer_Finding_View,
                Permissions.Transfer_Finding_Edit,
                Permissions.Transfer_Finding_Delete,
            )
        return check_object_permission(
            request,
            obj,
            Permissions.Transfer_Finding_View,
            Permissions.Transfer_Finding_Edit,
            Permissions.Transfer_Finding_Delete,
            Permissions.Transfer_Finding_Add,
            )
        
        
class UserHasInputFlowPermission(permissions.BasePermission):
    path_input_flow_post = re.compile(r"^/api/v2/input_flow/$")
    path_input_flow = re.compile(r"^/api/v2/input_flow/\d+/$")
    path_input_url = re.compile(r"^/api/v2/input_url/\d+/$")
    path_input_scenario = re.compile(r"^/api/v2/input_scenario/\d+/$")
    path_add_child = re.compile(r"^/api/v2/(input_flow/\d+/add_url|input_url/\d+/add_scenario)/$")

    def has_permission(self, request, view):
        if UserHasInputFlowPermission.path_input_flow_post.match(request.path):
            return check_post_permission(
                request,
                Engagement,
                "engagement",
                Permissions.Engagement_View,
            )
        return True

    def has_object_permission(self, request, view, obj):
        if UserHasInputFlowPermission.path_add_child.match(request.path):
            return user_has_permission(request.user, obj, Permissions.Input_Flow_Add)
        if (
            UserHasInputFlowPermission.path_input_flow_post.match(request.path)
            or UserHasInputFlowPermission.path_input_flow.match(request.path)
            or UserHasInputFlowPermission.path_input_url.match(request.path)
            or UserHasInputFlowPermission.path_input_scenario.match(request.path)
        ):
            return check_object_permission(
                request,
                obj,
                Permissions.Input_Flow_View,
                Permissions.Input_Flow_Edit,
                Permissions.Input_Flow_Delete,
                Permissions.Input_Flow_Add,
            )
        return True

class UserHasIaRecommendationPermission(permissions.BasePermission):
    path_post = re.compile(r"^/api/v2/metrics/ia_recommendation$")

    def has_permission(self, request, view):
        if (
            UserHasIaRecommendationPermission.path_post.match(request.path)
        ):
            return check_post_permission(
                request,
                Engagement,
                "engagement",
                Permissions.Engagement_View,
            )
        return True