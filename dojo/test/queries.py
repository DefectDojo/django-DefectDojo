from crum import get_current_user
from django.db.models import Exists, OuterRef, Q
from dojo.models import Test, Product_Member, Product_Type_Member, Test_Import, \
    Product_Group, Product_Type_Group
from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission


def get_authorized_tests(permission, product=None):
    user = get_current_user()

    if user is None:
        return Test.objects.none()

    tests = Test.objects.all()
    if product:
        tests = tests.filter(engagement__product=product)

    if user.is_superuser:
        return tests

    if user_has_global_permission(user, permission):
        return Test.objects.all()

    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef('engagement__product__prod_type_id'),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef('engagement__product_id'),
        user=user,
        role__in=roles)

    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('engagement__product__prod_type_id'),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('engagement__product_id'),
        group__users=user,
        role__in=roles)

    tests = tests.annotate(
        engagement__product__prod_type__member=Exists(authorized_product_type_roles),
        engagement__product__member=Exists(authorized_product_roles),
        engagement__product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        engagement__product__authorized_group=Exists(authorized_product_groups))

    tests = tests.filter(
        Q(engagement__product__prod_type__member=True) |
        Q(engagement__product__member=True) |
        Q(engagement__product__prod_type__authorized_group=True) |
        Q(engagement__product__authorized_group=True))

    return tests


def get_authorized_test_imports(permission):
    user = get_current_user()

    if user is None:
        return Test_Import.objects.none()

    if user.is_superuser:
        return Test_Import.objects.all()

    if user_has_global_permission(user, permission):
        return Test_Import.objects.all()

    roles = get_roles_for_permission(permission)
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef('test__engagement__product__prod_type_id'),
        user=user,
        role__in=roles)
    authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef('test__engagement__product_id'),
        user=user,
        role__in=roles)
    authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('test__engagement__product__prod_type_id'),
        group__users=user,
        role__in=roles)
    authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('test__engagement__product_id'),
        group__users=user,
        role__in=roles)
    test_imports = Test_Import.objects.annotate(
        test__engagement__product__prod_type__member=Exists(authorized_product_type_roles),
        test__engagement__product__member=Exists(authorized_product_roles),
        test__engagement__product__prod_type__authorized_group=Exists(authorized_product_type_groups),
        test__engagement__product__authorized_group=Exists(authorized_product_groups))
    test_imports = test_imports.filter(
        Q(test__engagement__product__prod_type__member=True) |
        Q(test__engagement__product__member=True) |
        Q(test__engagement__product__prod_type__authorized_group=True) |
        Q(test__engagement__product__authorized_group=True))

    return test_imports
