from django.db.models import Q
from dojo.models import Dojo_Group_Member, Product_Member, Product_Type_Member, \
    Product_Group, Product_Type_Group, Dojo_User
from dojo.authorization.authorization import get_roles_for_permission


def get_authorized_users_for_product_type(users, product_type, permission):
    roles = get_roles_for_permission(permission)
    product_type_members = Product_Type_Member.objects \
        .filter(product_type=product_type, role__in=roles)
    product_type_groups = Product_Type_Group.objects \
        .filter(product_type=product_type, role__in=roles)
    group_members = Dojo_Group_Member.objects. \
        filter(group__in=[ptg.group for ptg in product_type_groups])
    return users.filter(Q(id__in=[ptm.user.id for ptm in product_type_members]) |
        Q(id__in=[gm.user.id for gm in group_members]) |
        Q(global_role__role__in=roles) |
        Q(is_superuser=True))


def get_authorized_users_for_product_and_product_type(users, product, permission):
    if users is None:
        users = Dojo_User.objects.filter(is_active=True)

    roles = get_roles_for_permission(permission)
    product_members = Product_Member.objects \
        .filter(product=product, role__in=roles)
    product_type_members = Product_Type_Member.objects \
        .filter(product_type=product.prod_type, role__in=roles)
    product_groups = Product_Group.objects \
        .filter(product=product, role__in=roles)
    product_type_groups = Product_Type_Group.objects \
        .filter(product_type=product.prod_type, role__in=roles)
    group_members = Dojo_Group_Member.objects.filter(
        Q(group__in=[pg.group for pg in product_groups]) |
        Q(group__in=[ptg.group for ptg in product_type_groups]))
    return users.filter(Q(id__in=[pm.user.id for pm in product_members]) |
        Q(id__in=[ptm.user.id for ptm in product_type_members]) |
        Q(id__in=[gm.user.id for gm in group_members]) |
        Q(global_role__role__in=roles) |
        Q(is_superuser=True))
