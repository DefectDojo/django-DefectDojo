from crum import get_current_user
from django.db.models import Exists, OuterRef, Q
from django.conf import settings
from dojo.models import Product_Type, Product_Type_Member, Product_Type_Group
from dojo.authorization.authorization import get_roles_for_permission, user_has_permission, \
    role_has_permission, get_groups


def get_authorized_product_types(permission):
    user = get_current_user()

    if user is None:
        return Product_Type.objects.none()

    if user.is_superuser:
        return Product_Type.objects.all().order_by('name')

    if settings.FEATURE_AUTHORIZATION_V2:
        if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
            return Product_Type.objects.all().order_by('name')

        if hasattr(user, 'global_role') and user.global_role.role is not None and role_has_permission(user.global_role.role.id, permission):
            return Product_Type.objects.all().order_by('name')

        for group in get_groups(user):
            if hasattr(group, 'global_role') and group.global_role.role is not None and role_has_permission(group.global_role.role.id, permission):
                return Product_Type.objects.all().order_by('name')

        roles = get_roles_for_permission(permission)
        authorized_roles = Product_Type_Member.objects.filter(product_type=OuterRef('pk'),
            user=user,
            role__in=roles)
        authorized_groups = Product_Type_Group.objects.filter(
            product_type=OuterRef('pk'),
            group__users=user,
            role__in=roles)
        product_types = Product_Type.objects.annotate(
            member=Exists(authorized_roles),
            authorized_group=Exists(authorized_groups)).order_by('name')
        product_types = product_types.filter(Q(member=True) | Q(authorized_group=True))
    else:
        if user.is_staff:
            product_types = Product_Type.objects.all().order_by('name')
        else:
            product_types = Product_Type.objects.filter(authorized_users__in=[user]).order_by('name')
    return product_types


def get_authorized_members_for_product_type(product_type, permission):
    user = get_current_user()

    if user.is_superuser or user_has_permission(user, product_type, permission):
        return Product_Type_Member.objects.filter(product_type=product_type).order_by('user__first_name', 'user__last_name')
    else:
        return None


def get_authorized_product_type_members(permission):
    user = get_current_user()

    if user is None:
        return Product_Type_Member.objects.none()

    if user.is_superuser:
        return Product_Type_Member.objects.all()

    if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
        return Product_Type_Member.objects.all()

    if hasattr(user, 'global_role') and user.global_role.role is not None and role_has_permission(user.global_role.role.id, permission):
        return Product_Type_Member.objects.all()

    product_types = get_authorized_product_types(permission)
    return Product_Type_Member.objects.filter(product_type__in=product_types)


def get_authorized_product_type_members_for_user(user, permission):
    request_user = get_current_user()

    if request_user is None:
        return Product_Type_Member.objects.none()

    if request_user.is_superuser:
        return Product_Type_Member.objects.filter(user=user)

    if request_user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
        return Product_Type_Member.objects.all(user=user)

    if hasattr(user, 'global_role') and user.global_role.role is not None and role_has_permission(user.global_role.role.id, permission):
        return Product_Type_Member.objects.all(user=user)

    product_types = get_authorized_product_types(permission)
    return Product_Type_Member.objects.filter(user=user, product_type__in=product_types)


def get_authorized_product_type_groups(permission):
    user = get_current_user()

    if user is None:
        return Product_Type_Group.objects.none()

    if user.is_superuser:
        return Product_Type_Group.objects.all()

    if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
        return Product_Type_Group.objects.all()

    product_types = get_authorized_product_types(permission)
    return Product_Type_Group.objects.filter(product_type__in=product_types)
