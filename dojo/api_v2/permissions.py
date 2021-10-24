import re
from django.conf import settings
from django.core.exceptions import PermissionDenied
from rest_framework.exceptions import ParseError
from dojo.importers.reimporter.utils import PRODUCT_TYPE_NAME_AUTO, get_import_meta_data_from_dict, get_target_engagement_if_exists, get_target_product_if_exists, get_target_product_type_if_exists
from dojo.models import Endpoint, Engagement, Finding, Product_Type, Product, Test, Dojo_Group
from django.shortcuts import get_object_or_404
from rest_framework import permissions, serializers
from dojo.authorization.authorization import user_has_permission
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
        if request.method == 'POST':
            return request.user.is_staff
        else:
            return True

    def has_object_permission(self, request, view, obj):
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

        engagement_id, engagement_name, product_id, product_name, product_type_id, product_type_name = get_import_meta_data_from_dict(request.data)

        if engagement_id and not engagement_id.isdigit():
            raise serializers.ValidationError('engagement must be an integer')

        if product_id and not product_id.isdigit():
            raise serializers.ValidationError('product must be an integer')

        if product_type_id and not product_type_id.isdigit():
            raise serializers.ValidationError('product_type_id must be an integer')

        engagement = get_target_engagement_if_exists(engagement_id, engagement_name, product_id, product_name, product_type_id, product_type_name)
        product = get_target_product_if_exists(engagement_id, engagement_name, product_id, product_name, product_type_id, product_type_name)
        product_type = get_target_product_type_if_exists(engagement_id, engagement_name, product_id, product_name, product_type_id, product_type_name)

        if engagement:
            # existing engagement, nothing special to check
            return user_has_permission(request.user, engagement, Permissions.Import_Scan_Result)
        elif engagement_id:
            # engagement_id doesn't exist
            raise serializers.ValidationError('Engagement %s doesn''t exist' % engagement_id)
        elif product:
            # existing product, but user also needs permission to (auto)create a new engagement
            if settings.ALLOW_IMPORT_AUTO_CREATE:
                return True
            if not user_has_permission(request.user, product, Permissions.Import_Scan_Result):
                raise PermissionDenied('Permissions.Import_Scan_Result needed')
            if not user_has_permission(request.user, product, Permissions.Engagement_Add):
                raise PermissionDenied('Permissions.Engagement_Add needed')
            return True
        elif product_id:
            # product_id doesn't exist
            raise serializers.ValidationError('Product %s doesn''t exist' % product_id)
        elif product_type:
            if settings.ALLOW_IMPORT_AUTO_CREATE:
                return True
            if not user_has_permission(request.user, product_type, Permissions.Product_Type_Add_Product):
                raise PermissionDenied('Permissions.Product_Type_Add_Product needed')
            if not user_has_permission(request.user, product_type, Permissions.Engagement_Add):
                raise PermissionDenied('Permissions.Engagement_Add needed')
            if not user_has_permission(request.user, product_type, Permissions.Import_Scan_Result):
                raise PermissionDenied('Permissions.Import_Scan_Result needed')
            return True
        elif product_type_id:
            # product_type_id doesn't exist
            raise serializers.ValidationError('Product Type %s doesn''t exist' % product_type_id)
        else:
            # Here the scan will be uploaded into a new engagement, new product and product_type "Auto Created via API"
            # There is no permission suitable for this, so we use a settings.py entry
            # This is temporary as there will be permission/authorization improvements coming along which
            # can be used to make this better/nicer
            # For now new product_types cannot be created from here
            if product_type_name and product_type_name != PRODUCT_TYPE_NAME_AUTO:
                raise PermissionDenied('New Product Type cannot be created via auto created')

            if not product_name:
                raise serializers.ValidationError('Import needs engagement_id or product_id/name with engagement_name')

            if settings.ALLOW_IMPORT_EVERYONE:
                return True

            raise PermissionDenied('Import denied as product cannot be created, ALLOW_IMPORT_EVERYONE==False')


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
            return request.user.is_staff
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
        return check_post_permission(request, Test, 'test', Permissions.Import_Scan_Result)


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


class IsSuperUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_superuser


class UserHasEngagementPresetPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return check_post_permission(request, Product, 'product', Permissions.Product_Edit)

    def has_object_permission(self, request, view, obj):
        return check_object_permission(request, obj.product, Permissions.Product_View, Permissions.Product_Edit, Permissions.Product_Edit, Permissions.Product_Edit)
