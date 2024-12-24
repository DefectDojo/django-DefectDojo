import logging
from crum import get_current_user
from dojo.api_v2.api_error import ApiError
from django.db.models import Exists, OuterRef, Q
from dojo.authorization.roles_permissions import Permissions 
from dojo.authorization.exclusive_permissions import user_has_exclusive_permission_product
from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission
from dojo.models import (
    Product_Group,
    Product_Member,
    Product_Type_Group,
    Product_Type_Member,
    Test,
    Test_Import,
    ExclusivePermission)

logger = logging.getLogger(__name__)


def get_authorized_tests(permission, product=None):
    user = get_current_user()

    if user is None:
        return Test.objects.none()

    tests = Test.objects.all().order_by("id")
    if product:
        tests = tests.filter(engagement__product=product)

    if user.is_superuser:
        return tests

    if user_has_global_permission(user, permission):
        return tests

    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef("engagement__product__prod_type_id"),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef("engagement__product_id"),
        user=user,
        role__in=roles)

    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef("engagement__product__prod_type_id"),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef("engagement__product_id"),
        group__users=user,
        role__in=roles)

    tests = tests.annotate(
        engagement__product__prod_type__member=Exists(authorized_product_type_roles),
        engagement__product__member=Exists(authorized_product_roles),
        engagement__product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        engagement__product__authorized_group=Exists(authorized_product_groups))

    return tests.filter(
        Q(engagement__product__prod_type__member=True)
        | Q(engagement__product__member=True)
        | Q(engagement__product__prod_type__authorized_group=True)
        | Q(engagement__product__authorized_group=True))


def get_authorized_test_imports(permission):
    user = get_current_user()

    if user is None:
        return Test_Import.objects.none()

    if user.is_superuser:
        return Test_Import.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return Test_Import.objects.all().order_by("id")

    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef("test__engagement__product__prod_type_id"),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef("test__engagement__product_id"),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef("test__engagement__product__prod_type_id"),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef("test__engagement__product_id"),
        group__users=user,
        role__in=roles)
    test_imports = Test_Import.objects.annotate(
        test__engagement__product__prod_type__member=Exists(authorized_product_type_roles),
        test__engagement__product__member=Exists(authorized_product_roles),
        test__engagement__product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        test__engagement__product__authorized_group=Exists(authorized_product_groups)).order_by("id")
    return test_imports.filter(
        Q(test__engagement__product__prod_type__member=True)
        | Q(test__engagement__product__member=True)
        | Q(test__engagement__product__prod_type__authorized_group=True)
        | Q(test__engagement__product__authorized_group=True))


def get_exclude_red_team_tag(filtered_tests_qs,
                             product=None,
                             user=None):
    exclusive_permission = None

    if product is None and len(filtered_tests_qs) > 0:
        product = filtered_tests_qs[0].engagement.product

    if user is None:
        user = get_current_user()

    try:
        exclusive_permission = ExclusivePermission.objects.get(
            name="Product_Tag_Red_Team")
    except ExclusivePermission.DoesNotExist:
        logger.Error("Product_Tag_Red_Team does not exist")
        raise ApiError.not_found("Product_Tag_Red_Team does not exist")

    if exclusive_permission.is_active() is False:
        return filtered_tests_qs

    if (
        user_has_exclusive_permission_product(
            user, product, Permissions["Product_Tag_Red_Team"])
    ):
        pass
    else:
        tags_name = exclusive_permission\
            .get_validation_field("Product_Tag_Red_Team")\
            .split(",")
        filtered_tests_qs = filtered_tests_qs.exclude(
            tags__name__in=tags_name)
    return filtered_tests_qs