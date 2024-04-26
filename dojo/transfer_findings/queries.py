from crum import get_current_user
from dojo.models import Product
from dojo.product.queries import get_authorized_products
from dojo.authorization.authorization import user_has_global_permission
from dojo.api_v2.api_error import ApiError


def get_products_for_transfer_findings(permission, user=None):
    if user is None:
        user = get_current_user()
    
    if user.is_superuser:
        return Product.objects.all().order_by('name')

    if user_has_global_permission(user, permission):
        return Product.objects.all().order_by('name')

    try:
        products_member = get_authorized_products(permission, user)
        products = Product.objects.exclude(id__in=products_member.values_list('id', flat=True))
        return products

    except ApiError as e:
        raise ApiError(e.message)
