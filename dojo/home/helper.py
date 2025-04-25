from hashids import Hashids
from django.http import HttpRequest
from dojo.models import Product_Member, Product_Type_Member


def get_key_for_usermember_cache(request: HttpRequest) -> str:
    """
    Generate a cache key based on the user member (product and product_type).
    """
    if request.user.is_superuser:
        return "dashboard_cache_superusuario"
    # consultar member pro producto
    hashids = Hashids(min_length=8, salt="saltingfactor")
    permission_product = list(
        Product_Member.objects
        .filter(user=request.user)
        .values_list("id", flat=True)
        .order_by("id"))
    permission_product = hashids.encode(*permission_product)
    permission_product_type = list(
        Product_Type_Member.objects
        .filter(user=request.user)
        .values_list("id", flat=True)
        .order_by("id"))
    permission_product_type = hashids.encode(*permission_product_type)
    return f"dashboard:{permission_product}:{permission_product_type}"
