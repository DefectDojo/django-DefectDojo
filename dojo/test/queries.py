from crum import get_current_user
from django.conf import settings
from django.db.models import Exists, OuterRef, Q
from dojo.models import Test, Product_Member, Product_Type_Member, Test_Import
from dojo.authorization.authorization import get_roles_for_permission


def get_authorized_tests(permission):
    user = get_current_user()

    if user is None:
        return Test.objects.none()

    if user.is_superuser:
        return Test.objects.all()

    if settings.FEATURE_AUTHORIZATION_V2:
        if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
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
        tests = Test.objects.annotate(
            engagement__product__prod_type__member=Exists(authorized_product_type_roles),
            engagement__product__member=Exists(authorized_product_roles))
        tests = tests.filter(
            Q(engagement__product__prod_type__member=True) |
            Q(engagement__product__member=True))
    else:
        if user.is_staff:
            tests = Test.objects.all()
        else:
            tests = Test.objects.filter(
                Q(engagement__product__authorized_users__in=[user]) |
                Q(engagement__product__prod_type__authorized_users__in=[user]))
    return tests


def get_authorized_test_imports(permission):
    user = get_current_user()

    if user is None:
        return Test_Import.objects.none()

    if user.is_superuser:
        return Test_Import.objects.all()

    if settings.FEATURE_AUTHORIZATION_V2:
        if user.is_staff and settings.AUTHORIZATION_STAFF_OVERRIDE:
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
        test_imports = Test_Import.objects.annotate(
            test__engagement__product__prod_type__member=Exists(authorized_product_type_roles),
            test__engagement__product__member=Exists(authorized_product_roles))
        test_imports = test_imports.filter(
            Q(test__engagement__product__prod_type__member=True) |
            Q(test__engagement__product__member=True))
    else:
        if user.is_staff:
            test_imports = Test_Import.objects.all()
        else:
            test_imports = Test_Import.objects.filter(
                Q(test__engagement__product__authorized_users__in=[user]) |
                Q(test__engagement__product__prod_type__authorized_users__in=[user]))
    return test_imports
