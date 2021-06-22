from django.contrib.auth import get_user_model
from django.conf import settings
from django.db.models import Q
from dojo.models import Dojo_Group, Product_Member, Product_Type_Member, \
    Product_Group, Product_Type_Group
from dojo.authorization.authorization import get_roles_for_permission


def get_authorized_users_for_product_type(users, product_type, permission):
    if settings.FEATURE_AUTHORIZATION_V2:
        roles = get_roles_for_permission(permission)
        product_type_members = Product_Type_Member.objects \
            .filter(product_type=product_type, role__in=roles)
        product_type_groups = Product_Type_Group.objects \
            .filter(product_type=product_type, role__in=roles)
        groups = Dojo_Group.objects \
            .filter(id__in=[ptg.group.id for ptg in product_type_groups])
        return users.filter(Q(id__in=[ptm.user.id for ptm in product_type_members]) |
            Q(groups__id__in=[gu.id for gu in groups]) |
            Q(is_superuser=True))
    else:
        return users.filter(Q(id__in=product_type.authorized_users.all()) |
            Q(is_superuser=True) |
            Q(is_staff=True))


def get_authorized_users_for_product_and_product_type(users, product, permission):
    if users is None:
        User = get_user_model()
        users = User.objects.all()

    if settings.FEATURE_AUTHORIZATION_V2:
        roles = get_roles_for_permission(permission)
        product_members = Product_Member.objects \
            .filter(product=product, role__in=roles)
        product_type_members = Product_Type_Member.objects \
            .filter(product_type=product.prod_type, role__in=roles)
        product_groups = Product_Group.objects \
            .filter(product=product, role__in=roles)
        product_type_groups = Product_Type_Group.objects \
            .filter(product_type=product.prod_type, role__in=roles)
        groups = Dojo_Group.objects \
            .filter(Q(id__in=[pg.group.id for pg in product_groups]) | Q(id__in=[ptg.group.id for ptg in product_type_groups]))
        return users.filter(Q(id__in=[pm.user.id for pm in product_members]) |
            Q(id__in=[ptm.user.id for ptm in product_type_members]) |
            Q(groups__id__in=[gu.id for gu in groups]) |
            Q(is_superuser=True))
    else:
        return users.filter(Q(id__in=product.authorized_users.all()) |
            Q(id__in=product.prod_type.authorized_users.all()) |
            Q(is_superuser=True) |
            Q(is_staff=True))
