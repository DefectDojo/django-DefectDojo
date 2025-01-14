import logging
from django.core.exceptions import PermissionDenied

from dojo.authorization.roles_permissions import (
    Permissions,
    Roles,
    get_global_roles_with_permissions,
    get_roles_with_permissions,
)
from dojo.models import (
    App_Analysis,
    Component,
    Cred_Mapping,
    Dojo_Group,
    Dojo_Group_Member,
    Endpoint,
    Engagement,
    Finding,
    Finding_Group,
    Languages,
    Product,
    Product_API_Scan_Configuration,
    Product_Group,
    Product_Member,
    Product_Type,
    Product_Type_Group,
    Product_Type_Member,
    Stub_Finding,
    TransferFinding,
    Test,
    TransferFindingFinding,
    Risk_Acceptance
)
from dojo.engine_tools.models import FindingExclusion
from dojo.request_cache import cache_for_request
logger = logging.getLogger(__name__)


def user_has_configuration_permission(user, permission):
    if not user:
        return False

    if user.is_anonymous:
        return False

    return user.has_perm(permission)


def user_has_permission(user, obj, permission):
    if user.is_anonymous:
        return False

    if user.is_superuser:
        return True

    if isinstance(obj, Product_Type | Product):
        # Global roles are only relevant for product types, products and their
        # dependent objects
        if user_has_global_permission(user, permission):
            return True

    if isinstance(obj, Product_Type):
        # Check if the user has a role for the product type with the requested
        # permissions
        member = get_product_type_member(user, obj)
        if member is not None and role_has_permission(
            member.role.id, permission,
        ):
            return True
        # Check if the user is in a group with a role for the product type with
        # the requested permissions
        for product_type_group in get_product_type_groups(user, obj):
            if role_has_permission(product_type_group.role.id, permission):
                return True
        return False
    if (
        isinstance(obj, Product)
        and permission.value >= Permissions.Product_View.value
    ):
        # Products inherit permissions of their product type
        if user_has_permission(user, obj.prod_type, permission):
            return True

        # Check if the user has a role for the product with the requested
        # permissions
        member = get_product_member(user, obj)
        if member is not None and role_has_permission(
            member.role.id, permission,
        ):
            return True
        # Check if the user is in a group with a role for the product with the
        # requested permissions
        for product_group in get_product_groups(user, obj):
            if role_has_permission(product_group.role.id, permission):
                return True
        return False
    if (
        isinstance(obj, Engagement)
        and permission in Permissions.get_engagement_permissions()
    ):
        return user_has_permission(user, obj.product, permission)
    if (
        isinstance(obj, Test)
        and permission in Permissions.get_test_permissions()
    ):
        return user_has_permission(user, obj.engagement.product, permission)
    if (
        (isinstance(obj, Finding | Stub_Finding)
    ) and permission in Permissions.get_finding_permissions()) or (
        isinstance(obj, Finding_Group)
        and permission in Permissions.get_finding_group_permissions()):
        return user_has_permission(
            user, obj.test.engagement.product, permission,
        )
        
    if (
        isinstance(obj, Component)
        and permission in Permissions.get_component_permissions()
    ):
        return user_has_permission(
            user, obj.engagement, permission,
        )
    if (isinstance(obj, TransferFinding) and permission in Permissions.get_transfer_finding_permissions()):
        return custom_permissions_transfer_findings(user, obj, permission)
    if (isinstance(obj, TransferFindingFinding) and permission in Permissions.get_transfer_finding_finding_permissions()):
        return user_has_permission(user, obj.transfer_findings, permission)
    if (isinstance(obj, Risk_Acceptance) and permission in Permissions.get_engagement_permissions()):
        return user_has_permission(user, obj.engagement, permission)
    if (
        isinstance(obj, Finding_Group)
        and permission in Permissions.get_finding_group_permissions()
    ):
        return user_has_permission(
            user, obj.test.engagement.product, permission,
        )
    if (
        isinstance(obj, Endpoint)
        and permission in Permissions.get_endpoint_permissions()
    ) or (
        isinstance(obj, Languages)
        and permission in Permissions.get_language_permissions()
    ) or ((
        isinstance(obj, App_Analysis)
        and permission in Permissions.get_technology_permissions()
    ) or (
        isinstance(obj, Product_API_Scan_Configuration)
        and permission
        in Permissions.get_product_api_scan_configuration_permissions()
    )):
        return user_has_permission(user, obj.product, permission)
    if (
        isinstance(obj, Product_Type_Member)
        and permission in Permissions.get_product_type_member_permissions()
    ):
        if permission == Permissions.Product_Type_Member_Delete:
            # Every member is allowed to remove himself
            return obj.user == user or user_has_permission(
                user, obj.product_type, permission,
            )
        return user_has_permission(user, obj.product_type, permission)
    if (
        isinstance(obj, Product_Member)
        and permission in Permissions.get_product_member_permissions()
    ):
        if permission == Permissions.Product_Member_Delete:
            # Every member is allowed to remove himself
            return obj.user == user or user_has_permission(
                user, obj.product, permission,
            )
        return user_has_permission(user, obj.product, permission)
    if (
        isinstance(obj, Product_Type_Group)
        and permission in Permissions.get_product_type_group_permissions()
    ):
        return user_has_permission(user, obj.product_type, permission)
    if (
        isinstance(obj, Product_Group)
        and permission in Permissions.get_product_group_permissions()
    ):
        return user_has_permission(user, obj.product, permission)
    if (
        isinstance(obj, Dojo_Group)
        and permission in Permissions.get_group_permissions()
    ):
        # Check if the user has a role for the group with the requested
        # permissions
        group_member = get_group_member(user, obj)
        return group_member is not None and role_has_permission(
            group_member.role.id, permission,
        )
    if (
        isinstance(obj, Dojo_Group_Member)
        and permission in Permissions.get_group_member_permissions()
    ):
        if permission == Permissions.Group_Member_Delete:
            # Every user is allowed to remove himself
            return obj.user == user or user_has_permission(
                user, obj.group, permission,
            )
        return user_has_permission(user, obj.group, permission)
    if (
        isinstance(obj, Cred_Mapping)
        and permission in Permissions.get_credential_permissions()
    ):
        if obj.product:
            return user_has_permission(user, obj.product, permission)
        if obj.engagement:
            return user_has_permission(
                user, obj.engagement.product, permission,
            )
        if obj.test:
            return user_has_permission(
                user, obj.test.engagement.product, permission,
            )
        if obj.finding:
            return user_has_permission(
                user, obj.finding.test.engagement.product, permission,
            )
        return None
    msg = f"No authorization implemented for class {type(obj).__name__} and permission {permission}"
    raise NoAuthorizationImplementedError(msg)


def user_has_global_permission(user, permission):
    if not user:
        return False

    if user.is_anonymous:
        return False

    if user.is_superuser:
        return True

    if permission == Permissions.Product_Type_Add:
        if user_has_configuration_permission(user, "dojo.add_product_type"):
            return True

    if (
        hasattr(user, "global_role")
        and user.global_role.role is not None
        and role_has_global_permission(user.global_role.role.id, permission)
    ):
        return True

    for group in get_groups(user):
        if (
            hasattr(group, "global_role")
            and group.global_role.role is not None
            and role_has_global_permission(
                group.global_role.role.id, permission,
            )
        ):
            return True

    return False


def user_has_configuration_permission_or_403(user, permission):
    if not user_has_configuration_permission(user, permission):
        raise PermissionDenied


def user_has_permission_or_403(user, obj, permission):
    if not user_has_permission(user, obj, permission):
        raise PermissionDenied


def user_has_global_permission_or_403(user, permission):
    if not user_has_global_permission(user, permission):
        raise PermissionDenied


def get_roles_for_permission(permission):
    if not Permissions.has_value(permission):
        msg = f"Permission {permission} does not exist"
        raise PermissionDoesNotExistError(msg)
    roles_for_permissions = set()
    roles = get_roles_with_permissions()
    for role in roles:
        permissions = roles.get(role)
        if permission in permissions:
            roles_for_permissions.add(role)
    return roles_for_permissions


def role_has_permission(role, permission):
    if role is None:
        return False
    if not Roles.has_value(role):
        msg = f"Role {role} does not exist"
        raise RoleDoesNotExistError(msg)
    roles = get_roles_with_permissions()
    permissions = roles.get(role)
    if not permissions:
        return False
    return permission in permissions


def role_has_global_permission(role, permission):
    if role is None:
        return False
    if not Roles.has_value(role):
        msg = f"Role {role} does not exist"
        raise RoleDoesNotExistError(msg)
    roles = get_global_roles_with_permissions()
    permissions = roles.get(role)
    if permissions and permission in permissions:
        return True
    return role_has_permission(role, permission)


def custom_permissions_transfer_findings(user, obj, permission):

    if (
        hasattr(user, "global_role")
        and user.global_role.role is not None
        and role_has_global_permission(user.global_role.role.id, permission)
        ):
        return True

    def rule_permissions_transferfinding_accepted(obj, permission):
        transfer_finding_finding = obj.transfer_findings.filter(findings__risk_status__in=["Transfer Accepted", "Transfer Expired"])
        result = False
        if transfer_finding_finding:
            if permission in [Permissions.Transfer_Finding_View,
                              Permissions.Transfer_Finding_Finding_View,
                              Permissions.Transfer_Finding_Finding_Edit,
                              Permissions.Transfer_Finding_Finding_Delete]:
                result = True
        else:
            result = True
        return result

    member = get_product_type_member(user, obj.destination_product_type)
    if member is not None and role_has_permission(member.role.id, permission):
        return rule_permissions_transferfinding_accepted(obj, permission)
    member = get_product_type_member(user, obj.origin_product_type)
    if member is not None and role_has_permission(member.role.id, permission):
        return rule_permissions_transferfinding_accepted(obj, permission)
    member = get_product_member(user, obj.destination_product)
    if member is not None and role_has_permission(member.role.id, permission):
        return rule_permissions_transferfinding_accepted(obj, permission)
    member = get_product_member(user, obj.origin_product)
    if member is not None and role_has_permission(member.role.id, permission):
        return rule_permissions_transferfinding_accepted(obj, permission)


        

def check_permission_produc_type_member_add_owner(user):
    try:
        if user.is_superuser:
            return True
        if user.global_role:
            if user.global_role.role:
                return role_has_global_permission(user.global_role.role.id, Permissions.Product_Type_Member_Add_Owner)
        return False

    except Exception as e:
        logger.error(e)
        return False


def check_permission_product_member_add_owner(user):
    try:
        if user.is_superuser:
            return True
        if user.global_role:
            if user.global_role.role:
                return role_has_global_permission(user.global_role.role.id, Permissions.Product_Member_Add_Owner)
        return False

    except Exception as e:
        logger.error(e)
        return False


class NoAuthorizationImplementedError(Exception):
    def __init__(self, message):
        self.message = message


class PermissionDoesNotExistError(Exception):
    def __init__(self, message):
        self.message = message


class RoleDoesNotExistError(Exception):
    def __init__(self, message):
        self.message = message


def get_product_member(user, product):
    return get_product_member_dict(user).get(product.id)


@cache_for_request
def get_product_member_dict(user):
    pm_dict = {}
    for product_member in (
        Product_Member.objects.select_related("product")
        .select_related("role")
        .filter(user=user)
    ):
        pm_dict[product_member.product.id] = product_member
    return pm_dict


def get_product_type_member(user, product_type):
    return get_product_type_member_dict(user).get(product_type.id)


@cache_for_request
def get_product_type_member_dict(user):
    ptm_dict = {}
    for product_type_member in (
        Product_Type_Member.objects.select_related("product_type")
        .select_related("role")
        .filter(user=user)
    ):
        ptm_dict[product_type_member.product_type.id] = product_type_member
    return ptm_dict


def get_product_groups(user, product):
    return get_product_groups_dict(user).get(product.id, [])


@cache_for_request
def get_product_groups_dict(user):
    pg_dict = {}
    for product_group in (
        Product_Group.objects.select_related("product")
        .select_related("role")
        .filter(group__users=user)
    ):
        pgu_list = [] if pg_dict.get(product_group.product.id) is None else pg_dict[product_group.product.id]
        pgu_list.append(product_group)
        pg_dict[product_group.product.id] = pgu_list
    return pg_dict


def get_product_type_groups(user, product_type):
    return get_product_type_groups_dict(user).get(product_type.id, [])


@cache_for_request
def get_product_type_groups_dict(user):
    pgt_dict = {}
    for product_type_group in (
        Product_Type_Group.objects.select_related("product_type")
        .select_related("role")
        .filter(group__users=user)
    ):
        if pgt_dict.get(product_type_group.product_type.id) is None:
            pgtu_list = []
        else:
            pgtu_list = pgt_dict[product_type_group.product_type.id]
        pgtu_list.append(product_type_group)
        pgt_dict[product_type_group.product_type.id] = pgtu_list
    return pgt_dict


@cache_for_request
def get_groups(user):
    return Dojo_Group.objects.select_related("global_role").filter(users=user)


def get_group_member(user, group):
    return get_group_members_dict(user).get(group.id)


@cache_for_request
def get_group_members_dict(user):
    gu_dict = {}
    for group_member in (
        Dojo_Group_Member.objects.select_related("group")
        .select_related("role")
        .filter(user=user)
    ):
        gu_dict[group_member.group.id] = group_member
    return gu_dict
