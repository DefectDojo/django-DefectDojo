from django import template
from dojo.feature_decisions import new_permissions_enabled
from dojo.authorization.roles_permissions import Permissions, get_role_as_string
from dojo.authorization.authorization import user_has_permission

register = template.Library()


@register.simple_tag
def role_as_string(id):
    return get_role_as_string(id)


@register.simple_tag
def user_full_name(user):
    return '%s %s (%s)' % (user.first_name, user.last_name, user.username)


@register.simple_tag
def feature_new_permissions():
    return new_permissions_enabled()


@register.filter
def feature_new_permissions_or_user_is_staff(user):
    return new_permissions_enabled() or user.is_staff


@register.filter
def user_has_product_type_add_product_permission(user, product_type):
    return user_has_object_permission(user, product_type, Permissions.Product_Type_Add_Product)


@register.filter
def user_has_product_type_remove_member_permission(user, product_type_member):
    return user_has_object_permission(user, product_type_member, Permissions.Product_Type_Remove_Member)


@register.filter
def user_has_product_type_edit_permission(user, product_type):
    return user_has_object_permission(user, product_type, Permissions.Product_Type_Edit)


@register.filter
def user_has_product_type_manage_members_permission(user, product_type):
    return user_has_object_permission(user, product_type, Permissions.Product_Type_Manage_Members)


@register.filter
def user_has_product_type_delete_permission(user, product_type):
    return user_has_object_permission(user, product_type, Permissions.Product_Type_Delete)


def user_has_object_permission(user, obj, permission):
    if new_permissions_enabled():
        return user_has_permission(user, obj, permission)
    else:
        return user.is_staff
