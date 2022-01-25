import re
from rest_framework.exceptions import ParseError, PermissionDenied, ValidationError
from django.conf import settings
from dojo.api_v2.serializers import get_import_meta_data_from_dict, get_product_id_from_dict
from dojo.importers.reimporter.utils import get_target_engagement_if_exists, get_target_product_by_id_if_exists, \
    get_target_product_if_exists, get_target_test_if_exists,  \
    get_target_product_type_if_exists
from dojo.models import Endpoint, Engagement, Finding, Finding_Group, Product_Type, Product, Test, Dojo_Group
from django.shortcuts import get_object_or_404
from rest_framework import permissions, serializers
from dojo.authorization.authorization import user_has_global_permission, user_has_permission, user_has_configuration_permission
from dojo.authorization.roles_permissions import Permissions


def check_post_permission(request, post_model, post_pk, post_permission):
    if request.method == 'POST':
        if request.data.get(post_pk) is None:
            raise ParseError('Unable to check for permissions: Attribute \'{}\' is required'.format(post_pk))
        object = get_object_or_404(post_model, pk=request.data.get(post_pk))
        return user_has_permission(request.user, object, post_permission)
    else:
        return True


def check_object_permission(request, object, get_permission, put_permission, delete_permission, post_permission=None):
    if request.method == 'GET':
        return user_has_permission(request.user, object, get_permission)
    elif request.method == 'PUT' or request.method == 'PATCH':
        return user_has_permission(request.user, object, put_permission)
    elif request.method == 'DELETE':
        return user_has_permission(request.user, object, delete_permission)
    elif request.method == 'POST':
        return user_has_permission(request.user, object, post_permission)
    else:
        return False


class UserHasAppAnalysisPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(request, Product, 'product', Permissions.Technology_Add)

    def has_object_permission(self, request, view, obj):
        return check_object_permission(request, obj.product, Permissions.Technology_View, Permissions.Technology_Edit, Permissions.Technology_Delete)


class UserHasDojoGroupPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'GET':
            return user_has_configuration_permission(request.user, 'auth.view_group', 'staff')
        elif request.method == 'POST':
            return user_has_configuration_permission(request.user, 'auth.add_group', 'staff')
        else:
            return True

    def has_object_permission(self, request, view, obj):
        if request.method == 'GET':
            # Users need to be authorized to view groups in general and only the groups they are a member of
            # because with the group they can see user information that might be considered as confidential
            return user_has_configuration_permission(request.user, 'auth.view_group', 'staff') and user_has_permission(request.user, obj, Permissions.Group_View)
        else:
            return check_object_permission(request, obj, Permissions.Group_View, Permissions.Group_Edit, Permissions.Group_Delete)


class UserHasDojoGroupMemberPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(request, Dojo_Group, 'group', Permissions.Group_Manage_Members)

    def has_object_permission(self, request, view, obj):
        return check_object_permission(request, obj, Permissions.Group_View, Permissions.Group_Manage_Members, Permissions.Group_Member_Delete)


class UserHasDojoMetaPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'POST':
            has_permission_result = True
            product_id = request.data.get('product', None)
            if product_id:
                object = get_object_or_404(Product, pk=product_id)
                has_permission_result = has_permission_result and \
                    user_has_permission(request.user, object, Permissions.Product_Edit)
            finding_id = request.data.get('finding', None)
            if finding_id:
                object = get_object_or_404(Finding, pk=finding_id)
                has_permission_result = has_permission_result and \
                    user_has_permission(request.user, object, Permissions.Finding_Edit)
            endpoint_id = request.data.get('endpoint', None)
            if endpoint_id:
                object = get_object_or_404(Endpoint, pk=endpoint_id)
                has_permission_result = has_permission_result and \
                    user_has_permission(request.user, object, Permissions.Endpoint_Edit)
            return has_permission_result
        else:
            return True

    def has_object_permission(self, request, view, obj):
        has_permission_result = True
        product = obj.product
        if product:
            has_permission_result = has_permission_result and \
                check_object_permission(request, product, Permissions.Product_View, Permissions.Product_Edit, Permissions.Product_Edit)
        finding = obj.finding
        if finding:
            has_permission_result = has_permission_result and \
                check_object_permission(request, finding, Permissions.Finding_View, Permissions.Finding_Edit, Permissions.Finding_Edit)
        endpoint = obj.endpoint
        if endpoint:
            has_permission_result = has_permission_result and \
                check_object_permission(request, endpoint, Permissions.Endpoint_View, Permissions.Endpoint_Edit, Permissions.Endpoint_Edit)
        return has_permission_result


class UserHasToolProductSettingsPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(request, Product, 'product', Permissions.Product_Edit)

    def has_object_permission(self, request, view, obj):
        return check_object_permission(request, obj.product, Permissions.Product_View, Permissions.Product_Edit, Permissions.Product_Edit)


class UserHasEndpointPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(request, Product, 'product', Permissions.Endpoint_Add)

    def has_object_permission(self, request, view, obj):
        return check_object_permission(request, obj, Permissions.Endpoint_View, Permissions.Endpoint_Edit, Permissions.Endpoint_Delete)


class UserHasEndpointStatusPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(request, Endpoint, 'endpoint', Permissions.Endpoint_Edit)

    def has_object_permission(self, request, view, obj):
        return check_object_permission(request, obj.endpoint, Permissions.Endpoint_View, Permissions.Endpoint_Edit, Permissions.Endpoint_Edit)


class UserHasEngagementPermission(permissions.BasePermission):
    # Permission checks for related objects (like notes or metadata) can be moved
    # into a seperate class, when the legacy authorization will be removed.
    path_engagement_post = re.compile(r'^/api/v2/engagements/$')
    path_engagement = re.compile(r'^/api/v2/engagements/\d+/$')

    def has_permission(self, request, view):
        if UserHasEngagementPermission.path_engagement_post.match(request.path) or \
           UserHasEngagementPermission.path_engagement.match(request.path):
            return check_post_permission(request, Product, 'product', Permissions.Engagement_Add)
        else:
            # related object only need object permission
            return True

    def has_object_permission(self, request, view, obj):
        if UserHasEngagementPermission.path_engagement_post.match(request.path) or \
           UserHasEngagementPermission.path_engagement.match(request.path):
            return check_object_permission(request, obj, Permissions.Engagement_View, Permissions.Engagement_Edit, Permissions.Engagement_Delete)
        else:
            return check_object_permission(request, obj, Permissions.Engagement_View, Permissions.Engagement_Edit, Permissions.Engagement_Edit, Permissions.Engagement_Edit)


class UserHasFindingPermission(permissions.BasePermission):
    # Permission checks for related objects (like notes or metadata) can be moved
    # into a seperate class, when the legacy authorization will be removed.
    path_finding_post = re.compile(r'^/api/v2/findings/$')
    path_finding = re.compile(r'^/api/v2/findings/\d+/$')
    path_stub_finding_post = re.compile(r'^/api/v2/stub_findings/$')
    path_stub_finding = re.compile(r'^/api/v2/stub_findings/\d+/$')

    def has_permission(self, request, view):
        if UserHasFindingPermission.path_finding_post.match(request.path) or \
           UserHasFindingPermission.path_finding.match(request.path) or \
           UserHasFindingPermission.path_stub_finding_post.match(request.path) or \
           UserHasFindingPermission.path_stub_finding.match(request.path):
            return check_post_permission(request, Test, 'test', Permissions.Finding_Add)
        else:
            # related object only need object permission
            return True

    def has_object_permission(self, request, view, obj):
        if UserHasFindingPermission.path_finding_post.match(request.path) or \
           UserHasFindingPermission.path_finding.match(request.path) or \
           UserHasFindingPermission.path_stub_finding_post.match(request.path) or \
           UserHasFindingPermission.path_stub_finding.match(request.path):
            return check_object_permission(request, obj, Permissions.Finding_View, Permissions.Finding_Edit, Permissions.Finding_Delete)
        else:
            return check_object_permission(request, obj, Permissions.Finding_View, Permissions.Finding_Edit, Permissions.Finding_Edit, Permissions.Finding_Edit)


class UserHasImportPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # permission check takes place before validation, so we don't have access to serializer.validated_data()
        # and we have to validate ourselves unfortunately

        _, _, _, engagement_id, engagement_name, product_name, product_type_name, auto_create_context = get_import_meta_data_from_dict(request.data)
        product_type = get_target_product_type_if_exists(product_type_name)
        product = get_target_product_if_exists(product_name, product_type_name)
        engagement = get_target_engagement_if_exists(engagement_id, engagement_name, product)

        if engagement:
            # existing engagement, nothing special to check
            return user_has_permission(request.user, engagement, Permissions.Import_Scan_Result)
        elif engagement_id:
            # engagement_id doesn't exist
            raise serializers.ValidationError("Engagement '%s' doesn''t exist" % engagement_id)

        if not auto_create_context:
            raise_no_auto_create_import_validation_error(None, None, engagement_name, product_name, product_type_name, engagement, product, product_type,
                                                "Need engagement_id or product_name + engagement_name to perform import")
        else:
            # the engagement doesn't exist, so we need to check if the user has requested and is allowed to use auto_create
            return check_auto_create_permission(request.user, product, product_name, engagement, engagement_name, product_type, product_type_name,
                                                 "Need engagement_id or product_name + engagement_name to perform import")


class UserHasMetaImportPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # permission check takes place before validation, so we don't have access to serializer.validated_data()
        # and we have to validate ourselves unfortunately

        _, _, _, _, _, product_name, _, _ = get_import_meta_data_from_dict(request.data)
        product = get_target_product_if_exists(product_name)
        if not product:
            product_id = get_product_id_from_dict(request.data)
            product = get_target_product_by_id_if_exists(product_id)

        if product:
            # existing product, nothing special to check
            return user_has_permission(request.user, product, Permissions.Import_Scan_Result)
        elif product_id:
            # product_id doesn't exist
            raise serializers.ValidationError("product '%s' doesn''t exist" % product_id)
        else:
            raise serializers.ValidationError("Need product_id or product_name to perform import")


class UserHasProductPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(request, Product_Type, 'prod_type', Permissions.Product_Type_Add_Product)

    def has_object_permission(self, request, view, obj):
        return check_object_permission(request, obj, Permissions.Product_View, Permissions.Product_Edit, Permissions.Product_Delete)


class UserHasProductMemberPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(request, Product, 'product', Permissions.Product_Manage_Members)

    def has_object_permission(self, request, view, obj):
        return check_object_permission(request, obj, Permissions.Product_View, Permissions.Product_Manage_Members, Permissions.Product_Member_Delete)


class UserHasProductGroupPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(request, Product, 'product', Permissions.Product_Group_Add)

    def has_object_permission(self, request, view, obj):
        return check_object_permission(request, obj, Permissions.Product_Group_View, Permissions.Product_Group_Edit, Permissions.Product_Group_Delete)


class UserHasProductTypePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'POST':
            return user_has_global_permission(request.user, Permissions.Product_Type_Add)
        else:
            return True

    def has_object_permission(self, request, view, obj):
        return check_object_permission(request, obj, Permissions.Product_Type_View, Permissions.Product_Type_Edit, Permissions.Product_Type_Delete)


class UserHasProductTypeMemberPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(request, Product_Type, 'product_type', Permissions.Product_Type_Manage_Members)

    def has_object_permission(self, request, view, obj):
        return check_object_permission(request, obj, Permissions.Product_Type_View, Permissions.Product_Type_Manage_Members, Permissions.Product_Type_Member_Delete)


class UserHasProductTypeGroupPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(request, Product_Type, 'product_type', Permissions.Product_Type_Group_Add)

    def has_object_permission(self, request, view, obj):
        return check_object_permission(request, obj, Permissions.Product_Type_Group_View, Permissions.Product_Type_Group_Edit, Permissions.Product_Type_Group_Delete)


class UserHasReimportPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # permission check takes place before validation, so we don't have access to serializer.validated_data()
        # and we have to validate ourselves unfortunately

        test_id, test_title, scan_type, _, engagement_name, product_name, product_type_name, auto_create_context = get_import_meta_data_from_dict(request.data)

        product_type = get_target_product_type_if_exists(product_type_name)
        product = get_target_product_if_exists(product_name, product_type_name)
        engagement = get_target_engagement_if_exists(None, engagement_name, product)
        test = get_target_test_if_exists(test_id, test_title, scan_type, engagement)

        if test:
            # existing test, nothing special to check
            return user_has_permission(request.user, test, Permissions.Import_Scan_Result)
        elif test_id:
            # test_id doesn't exist
            raise serializers.ValidationError("Test '%s' doesn't exist" % test_id)

        if not auto_create_context:
            raise_no_auto_create_import_validation_error(test_title, scan_type, engagement_name, product_name, product_type_name, engagement, product, product_type,
                                                "Need test_id or product_name + engagement_name + scan_type to perform reimport")
        else:
            # the test doesn't exist, so we need to check if the user has requested and is allowed to use auto_create
            return check_auto_create_permission(request.user, product, product_name, engagement, engagement_name, product_type, product_type_name,
                                                "Need test_id or product_name + engagement_name + scan_type to perform reimport")


class UserHasTestPermission(permissions.BasePermission):
    # Permission checks for related objects (like notes or metadata) can be moved
    # into a seperate class, when the legacy authorization will be removed.
    path_tests_post = re.compile(r'^/api/v2/tests/$')
    path_tests = re.compile(r'^/api/v2/tests/\d+/$')

    def has_permission(self, request, view):
        if UserHasTestPermission.path_tests_post.match(request.path) or \
           UserHasTestPermission.path_tests.match(request.path):
            return check_post_permission(request, Engagement, 'engagement', Permissions.Test_Add)
        else:
            # related object only need object permission
            return True

    def has_object_permission(self, request, view, obj):
        if UserHasTestPermission.path_tests_post.match(request.path) or \
           UserHasTestPermission.path_tests.match(request.path):
            return check_object_permission(request, obj, Permissions.Test_View, Permissions.Test_Edit, Permissions.Test_Delete)
        else:
            return check_object_permission(request, obj, Permissions.Test_View, Permissions.Test_Edit, Permissions.Test_Edit, Permissions.Test_Edit)


class UserHasTestImportPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(request, Test, 'test', Permissions.Test_Edit)

    def has_object_permission(self, request, view, obj):
        return check_object_permission(request, obj.test, Permissions.Test_View, Permissions.Test_Edit, Permissions.Test_Delete)


class UserHasLanguagePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(request, Product, 'product', Permissions.Language_Add)

    def has_object_permission(self, request, view, obj):
        return check_object_permission(request, obj, Permissions.Language_View, Permissions.Language_Edit, Permissions.Language_Delete)


class UserHasProductAPIScanConfigurationPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(request, Product, 'product', Permissions.Product_API_Scan_Configuration_Add)

    def has_object_permission(self, request, view, obj):
        return check_object_permission(request, obj, Permissions.Product_API_Scan_Configuration_View, Permissions.Product_API_Scan_Configuration_Edit, Permissions.Product_API_Scan_Configuration_Delete)


class UserHasJiraProductPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'POST':
            has_permission_result = True
            engagement_id = request.data.get('engagement', None)
            if engagement_id:
                object = get_object_or_404(Engagement, pk=engagement_id)
                has_permission_result = has_permission_result and \
                    user_has_permission(request.user, object, Permissions.Engagement_Edit)
            product_id = request.data.get('product', None)
            if product_id:
                object = get_object_or_404(Product, pk=product_id)
                has_permission_result = has_permission_result and \
                    user_has_permission(request.user, object, Permissions.Product_Edit)
            return has_permission_result
        else:
            return True

    def has_object_permission(self, request, view, obj):
        has_permission_result = True
        engagement = obj.engagement
        if engagement:
            has_permission_result = has_permission_result and \
                check_object_permission(request, engagement, Permissions.Engagement_View, Permissions.Engagement_Edit, Permissions.Engagement_Edit)
        product = obj.product
        if product:
            has_permission_result = has_permission_result and \
                check_object_permission(request, product, Permissions.Product_View, Permissions.Product_Edit, Permissions.Product_Edit)
        return has_permission_result


class UserHasJiraIssuePermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method == 'POST':
            has_permission_result = True
            engagement_id = request.data.get('engagement', None)
            if engagement_id:
                object = get_object_or_404(Engagement, pk=engagement_id)
                has_permission_result = has_permission_result and \
                    user_has_permission(request.user, object, Permissions.Engagement_Edit)
            finding_id = request.data.get('finding', None)
            if finding_id:
                object = get_object_or_404(Finding, pk=finding_id)
                has_permission_result = has_permission_result and \
                    user_has_permission(request.user, object, Permissions.Finding_Edit)
            finding_group_id = request.data.get('finding_group', None)
            if finding_group_id:
                object = get_object_or_404(Finding_Group, pk=finding_group_id)
                has_permission_result = has_permission_result and \
                    user_has_permission(request.user, object, Permissions.Finding_Group_Edit)
            return has_permission_result
        else:
            return True

    def has_object_permission(self, request, view, obj):
        has_permission_result = True
        engagement = obj.engagement
        if engagement:
            has_permission_result = has_permission_result and \
                check_object_permission(request, engagement, Permissions.Engagement_View, Permissions.Engagement_Edit, Permissions.Engagement_Edit)
        finding = obj.finding
        if finding:
            has_permission_result = has_permission_result and \
                check_object_permission(request, finding, Permissions.Finding_View, Permissions.Finding_Edit, Permissions.Finding_Edit)
        finding_group = obj.finding_group
        if finding_group:
            has_permission_result = has_permission_result and \
                check_object_permission(request, finding_group, Permissions.Finding_Group_View, Permissions.Finding_Group_Edit, Permissions.Finding_Group_Edit)
        return has_permission_result


class IsSuperUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_superuser


class UserHasEngagementPresetPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(request, Product, 'product', Permissions.Product_Edit)

    def has_object_permission(self, request, view, obj):
        return check_object_permission(request, obj.product, Permissions.Product_View, Permissions.Product_Edit, Permissions.Product_Edit, Permissions.Product_Edit)


def raise_no_auto_create_import_validation_error(test_title, scan_type, engagement_name, product_name, product_type_name, engagement, product, product_type, error_message):
    # check for mandatory fields first
    if not product_name:
        raise ValidationError("product_name parameter missing")

    if not engagement_name:
        raise ValidationError("engagement_name parameter missing")

    if product_type_name and not product_type:
        raise serializers.ValidationError("Product Type '%s' doesn't exist" % (product_type_name))

    if product_name and not product:
        if product_type_name:
            raise serializers.ValidationError("Product '%s' doesn't exist in Product_Type '%s'" % (product_name, product_type_name))
        else:
            raise serializers.ValidationError("Product '%s' doesn't exist" % product_name)

    if engagement_name and not engagement:
        raise serializers.ValidationError("Engagement '%s' doesn't exist in Product '%s'" % (engagement_name, product_name))

    # these are only set for reimport
    if test_title:
        raise serializers.ValidationError("Test '%s' with scan_type '%s' doesn't exist in Engagement '%s'" % (test_title, scan_type, engagement_name))

    if scan_type:
        raise serializers.ValidationError("Test with scan_type '%s' doesn't exist in Engagement '%s'" % (scan_type, engagement_name))

    raise ValidationError(error_message)


def check_auto_create_permission(user, product, product_name, engagement, engagement_name, product_type, product_type_name, error_message):
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
        raise ValidationError("product_name parameter missing")

    if not engagement_name:
        raise ValidationError("engagement_name parameter missing")

    if engagement:
        # existing engagement, nothing special to check
        return user_has_permission(user, engagement, Permissions.Import_Scan_Result)

    if product and product_name and engagement_name:
        if not user_has_permission(user, product, Permissions.Engagement_Add):
            raise PermissionDenied("No permission to create engagements in product '%s'", product_name)

        if not user_has_permission(user, product, Permissions.Import_Scan_Result):
            raise PermissionDenied("No permission to import scans into product '%s'", product_name)

        # all good
        return True

    if not product and product_name:
        if not product_type_name:
            raise serializers.ValidationError("Product '%s' doesn't exist and no product_type_name provided to create the new product in" % product_name)

        if not product_type:
            if not user_has_global_permission(user, Permissions.Product_Type_Add):
                raise PermissionDenied("No permission to create product_type '%s'", product_type_name)
            # new product type can be created with current user as owner, so all objects in it can be created as well
            return True
        else:
            if not user_has_permission(user, product_type, Permissions.Product_Type_Add_Product):
                raise PermissionDenied("No permission to create products in product_type '%s'", product_type)

        # product can be created, so objects in it can be created as well
        return True

    raise ValidationError(error_message)


class UserHasConfigurationPermissionStaff(permissions.DjangoModelPermissions):

    # Override map to also provide 'view' permissions
    perms_map = {
        'GET': ['%(app_label)s.view_%(model_name)s'],
        'OPTIONS': [],
        'HEAD': [],
        'POST': ['%(app_label)s.add_%(model_name)s'],
        'PUT': ['%(app_label)s.change_%(model_name)s'],
        'PATCH': ['%(app_label)s.change_%(model_name)s'],
        'DELETE': ['%(app_label)s.delete_%(model_name)s'],
    }

    def has_permission(self, request, view):
        if settings.FEATURE_CONFIGURATION_AUTHORIZATION:
            return super().has_permission(request, view)
        else:
            return request.user.is_staff


class UserHasConfigurationPermissionSuperuser(permissions.DjangoModelPermissions):

    # Override map to also provide 'view' permissions
    perms_map = {
        'GET': ['%(app_label)s.view_%(model_name)s'],
        'OPTIONS': [],
        'HEAD': [],
        'POST': ['%(app_label)s.add_%(model_name)s'],
        'PUT': ['%(app_label)s.change_%(model_name)s'],
        'PATCH': ['%(app_label)s.change_%(model_name)s'],
        'DELETE': ['%(app_label)s.delete_%(model_name)s'],
    }

    def has_permission(self, request, view):
        if settings.FEATURE_CONFIGURATION_AUTHORIZATION:
            return super().has_permission(request, view)
        else:
            return request.user.is_superuser
