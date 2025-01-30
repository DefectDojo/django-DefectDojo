import logging
import crum
from django.conf import settings
from typing import Union
from django.core.exceptions import PermissionDenied
from dojo.api_v2.api_error import ApiError
from dojo.utils import get_product
from dojo.utils import user_is_contacts
from dojo.authorization.roles_permissions import Permissions 
from dojo.authorization.authorization import (
    user_has_global_permission,
    get_product_type_member,
    role_has_permission)
from dojo.models import (
    Dojo_User,
    Test,
    Product,
    ExclusivePermission,
    Product_Member,
    Finding,
    Product_Type,
    Vulnerability_Id)
logger = logging.getLogger(__name__)


def get_exclusive_permission_object(name):
    try:
        exclusive_permission = ExclusivePermission.objects.get(
            name=name)
    except ExclusivePermission.DoesNotExist:
        logger.error(f"{name} does not exist")
        raise ApiError.not_found(f"{name} does not exist")

    return exclusive_permission


def get_exclusive_permission(user: Dojo_User,
                             product: Product) -> list[Permissions]:
    products_members = Product_Member.objects.filter(
        product=product,
        user=user)
    permissions = []
    if products_members.exists():
        permissions = ExclusivePermission.objects.filter(
            members__in=products_members)
        try:
            permissions = [
                Permissions[permission.name]
                for permission in permissions
                ]
        except KeyError as e:
            logger.error(f"The permit {e} has not been defined\
                in class Permissions")

    return permissions


class RulePermission:
    def __init__(self, permission: Permissions, user: Dojo_User, obj: object):
        self.permission = permission
        self.user = user
        self.object = obj

    def rule_Product_Tag_Red_Team(self, *args, **kwargs) -> bool:
        """Rule Custom for permission

        Returns:
            bool: True if user has permission, False otherwise
        """
        product = None
        validation_tags = ExclusivePermission.get_validation_field(
            self.permission.name)
        if isinstance(self.object, Test) or isinstance(self.object, Finding):
            product = get_product(self.object)
            tags_objects = list(
                self.object.tags.all().values_list("name", flat=True)
                )
            if any(tag in validation_tags for tag in tags_objects):
                return self.permission in get_exclusive_permission(
                    self.user,
                    product)
            else:
                # Tag not found in object
                return True
        elif isinstance(self.object, Product):
            product = self.object
            return self.permission in get_exclusive_permission(
                self.user,
                product)
        else:
            raise ApiError.internal_server_error(
               detail=f"Object type {type(self.object)} not implemented")

    def apply_rule(self, *args, **kwargs) -> bool:

        rule_dict = {
            "Product_Tag_Red_Team": self.rule_Product_Tag_Red_Team
        }

        rule_function = rule_dict.get(self.permission.name, None)
        if rule_function:
            return rule_function(*args, **kwargs)
        return False


def user_has_permission(user: Dojo_User,
                        permission: Permissions,
                        obj) -> bool:

    engine_rule = RulePermission(
        user=user,
        permission=permission,
        obj=obj)

    rule_response = engine_rule.apply_rule()
    return rule_response


def user_has_permission_or_404(
    user: Dojo_User,
    permission: Permissions,
    obj: object) -> bool:

    engine_rule = RulePermission(
        user=user,
        permission=permission,
        obj=obj)

    rule_response = engine_rule.apply_rule()
    if rule_response is False:
        raise PermissionDenied
    return rule_response

def get_members(user, obj):
    product = get_product(obj)
    product_type = product.prod_type
    members = get_product_type_member(user, product_type)
    return members


def user_has_exclusive_permission(
        user: Dojo_User,
        obj: Union[Product_Type, Product],
        permission: Permissions) -> bool:
    
    exclusive_permission = get_exclusive_permission_object(
        name="Product_Tag_Red_Team")
    
    if exclusive_permission.is_active() is False:
        return True
        
    if user is None:
        user = crum.get_current_user()

    member = get_members(user, obj)

    if user is None:
        user = crum.get_current_user()

    if user.is_anonymous:
        return False
    if user.is_superuser:
        return True
    if user_has_global_permission(user, permission):
        return True
    if user_is_contacts(user,
                        obj,
                        settings.CONTACTS_ASSIGN_EXCLUSIVE_PERMISSIONS):
        return True
    if member is not None and role_has_permission(
        member.role.id,
        permission
    ):
        return True
    return user_has_permission(
        user=user,
        obj=obj,
        permission=permission)


def user_has_exclusive_permission_product_or_404(
        user: Dojo_User,
        obj: object,
        permission: Permissions) -> bool:
    
    if settings.ENABLE_FILTER_FOR_TAG_RED_TEAM:
        return True

    if user is None:
        user = crum.get_current_user()
    
    exclusive_permission = get_exclusive_permission_object(
        name="Product_Tag_Red_Team")
    
    if exclusive_permission.is_active() is False:
        return True

    member = get_product_type_member(user, obj)

    if user.is_anonymous:
        raise PermissionDenied
    if user.is_superuser:
        return True
    if user_has_global_permission(user, permission):
        return True
    if member is not None and role_has_permission(
            member.role.id, permission):
        return True

    return user_has_permission_or_404(
        user=user,
        obj=obj,
        permission=permission)


def exclude_tags(objs, tags):
    return objs.exclude(tags__name__in=tags)
    

def exclude_test_or_finding_with_tag(
        objs,
        product=None,
        user=None):

    exclusive_permission = None
    if not objs.exists():
        return objs

    exclusive_permission = get_exclusive_permission_object(
        name="Product_Tag_Red_Team")
    
    if exclusive_permission.is_active() is False:
        return objs
    
    tags_name = exclusive_permission\
        .get_validation_field("Product_Tag_Red_Team")\
        .split(",")

    if (product is None
        and isinstance(objs.first(), Test)
        or isinstance(objs.first(), Finding)):
        product = get_product(objs.first())

    elif isinstance(objs.first, Vulnerability_Id):
        return exclude_tags(objs, tags_name)
        
    if user is None:
        user = crum.get_current_user()

    if (
        user_has_exclusive_permission(
            user, product, Permissions["Product_Tag_Red_Team"])
    ):
        return objs
    return exclude_tags(objs, tags_name)
