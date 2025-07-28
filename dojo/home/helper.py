import hashlib
import logging
from hashids import Hashids
from django.http import HttpRequest
from dojo.models import Product_Member, Product_Type_Member
logger = logging.getLogger(__name__)


def encode_string(value):
    key = hashlib.md5(value.encode()).hexdigest()[:12]
    return key


def get_key_for_usermember_cache(request: HttpRequest) -> str:
    """
    Generate a cache key based on the user member (product and product_type).
    """
    if request.user.is_superuser:
        return "dashboard_cache_superusuario"
    hashids = Hashids(min_length=8, salt="saltingfactor")
    permission_product = list(
        Product_Member.objects
        .filter(user=request.user)
        .values_list("product", flat=True)
        .order_by("product"))
    permission_product = hashids.encode(*permission_product)
    permission_product_type = list(
        Product_Type_Member.objects
        .filter(user=request.user)
        .values_list("product_type", flat=True)
        .order_by("product_type"))
    permission_product_type = hashids.encode(*permission_product_type)
    return f"dashboard:{permission_product}:{permission_product_type}"


def get_key_for_user_and_urlpath(
        request: HttpRequest,
        base_key="default"
) -> str:
    """
    Generate a cache key based on the user and the URL path query.
    """
    key = encode_string(request.META.get("QUERY_STRING", ""))
    key = f"{base_key}:{request.user.username}:{key}"
    logger.debug(f"REPORT FINDING: calculate key url path {key}")
    return key
