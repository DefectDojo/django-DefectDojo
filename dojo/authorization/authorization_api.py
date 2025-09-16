from dojo.authorization.roles_permissions import Permissions 
from dojo.authorization.authorization import NoAuthorizationImplementedError
from dojo.authorization.authorization import (
    user_has_global_permission,
    get_product_type_member,
    role_has_permission,
    get_product_type_groups,
    get_product_member,
    get_product_groups,
    )
from dojo.models import (
    Product,
    Product_Type,
    Engagement,
    Test,
    Finding,
    Stub_Finding,
    Finding_Group,
    Component,
    TransferFinding,
    TransferFindingFinding,
    Risk_Acceptance,
    Endpoint,
    Languages,
    App_Analysis,
    Product_API_Scan_Configuration,
    Product_Type_Member,
    Product_Member,
    Product_Type_Group,
    Product_Group,
    Dojo_Group,
    Dojo_Group_Member,
    Cred_Mapping
)

def user_has_permission(user, obj, permission):
    if user.is_anonymous:
        return []

    if user.is_superuser:
        return [] 

    if isinstance(obj, Product_Type | Product):
        if user_has_global_permission(user, permission):
            return Permissions.get_product_type_member_permissions()

    if isinstance(obj, Product_Type):
        member = get_product_type_member(user, obj)
        if member is not None and role_has_permission(
            member.role.id, permission,
        ):
            return Permissions.get_product_type_member_permissions()
        for product_type_group in get_product_type_groups(user, obj):
            if role_has_permission(product_type_group.role.id, permission):
                return Permissions.get_product_type_group_permissions()
        return False
    if (
        isinstance(obj, Product)
        and permission.value >= Permissions.Product_View.value
    ):
        if user_has_permission(user, obj.prod_type, permission):
            return Permissions.get_product_permissions()

        member = get_product_member(user, obj)
        for product_group in get_product_groups(user, obj):
            if role_has_permission(product_group.role.id, permission):
                return Permissions.get_product_group_permissions()
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
    if isinstance(obj, Finding | Stub_Finding):
        return Permissions.get_finding_group_permissions()

    if (
        isinstance(obj, Component)
        and permission in Permissions.get_component_permissions()
    ):
        if user_has_permission(
            user, obj.engagement, permission,
        ):
            return Permissions.get_component_permissions()
    msg = f"No authorization implemented for class {type(obj).__name__} and permission {permission}"
    raise NoAuthorizationImplementedError(msg)