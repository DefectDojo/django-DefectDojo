import re

from rest_framework.exceptions import ParseError
from dojo.models import Endpoint, Engagement, Finding, Product_Type, Product, Test, Dojo_Group
from django.shortcuts import get_object_or_404
from rest_framework import permissions
from dojo.authorization.authorization import user_has_permission
from dojo.authorization.roles_permissions import Permissions


def check_post_permission(request, post_model, post_pk, post_permission):
    if request.method == 'POST':
        if request.data.get(post_pk) is None:
            raise ParseError('Attribute \'{}\' is required'.format(post_pk))
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
        return check_post_permission(request, Product, 'product', Permissions.Product_Edit)

    def has_object_permission(self, request, view, obj):
        return check_object_permission(request, obj.product, Permissions.Product_View, Permissions.Product_Edit, Permissions.Product_Edit)


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
        return check_post_permission(request, Engagement, 'engagement', Permissions.Import_Scan_Result)


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


class IsSuperUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_superuser
