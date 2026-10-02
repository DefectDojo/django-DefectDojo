try:
    from dojo.authorization.query_filters import get_auth_filter
except ImportError:
    def get_auth_filter(key): return None

from dojo.models import (
    Dojo_User,
)
from dojo.request_cache import cache_for_request_or_task


def get_authorized_users_for_product_type(users, product_type, permission):
    impl = get_auth_filter("user.get_authorized_users_for_product_type")
    if impl:
        return impl(users, product_type, permission)
    return users


def get_authorized_users_for_product_and_product_type(users, product, permission):
    impl = get_auth_filter("user.get_authorized_users_for_product_and_product_type")
    if impl:
        return impl(users, product, permission)
    return users


# Cached because it is a complex SQL query and it is called 3 times for the engagement lists in products
@cache_for_request_or_task
def get_authorized_users(permission, user=None):
    impl = get_auth_filter("user.get_authorized_users")
    if impl:
        return impl(permission, user=user)
    return Dojo_User.objects.all().order_by("first_name", "last_name")
