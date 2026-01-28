from crum import get_current_user
from django.db.models import Q, Subquery

from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission
from dojo.models import Product_Group, Product_Member, Product_Type_Group, Product_Type_Member, Test, Test_Import
from dojo.request_cache import cache_for_request


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
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
        return Test.objects.all().order_by("id")

    roles = get_roles_for_permission(permission)

    # Get authorized product/product_type IDs via subqueries
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_roles = Product_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_id")

    authorized_product_type_groups = Product_Type_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_groups = Product_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_id")

    # Filter using IN with Subquery - no annotations needed
    return tests.filter(
        Q(engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(engagement__product_id__in=Subquery(authorized_product_groups)),
    )


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_test_imports(permission):
    user = get_current_user()

    if user is None:
        return Test_Import.objects.none()

    if user.is_superuser:
        return Test_Import.objects.all().order_by("id")

    if user_has_global_permission(user, permission):
        return Test_Import.objects.all().order_by("id")

    roles = get_roles_for_permission(permission)

    # Get authorized product/product_type IDs via subqueries
    authorized_product_type_roles = Product_Type_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_roles = Product_Member.objects.filter(
        user=user, role__in=roles,
    ).values("product_id")

    authorized_product_type_groups = Product_Type_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_type_id")

    authorized_product_groups = Product_Group.objects.filter(
        group__users=user, role__in=roles,
    ).values("product_id")

    # Filter using IN with Subquery - no annotations needed
    return Test_Import.objects.filter(
        Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_roles))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_roles))
        | Q(test__engagement__product__prod_type_id__in=Subquery(authorized_product_type_groups))
        | Q(test__engagement__product_id__in=Subquery(authorized_product_groups)),
    ).order_by("id")
