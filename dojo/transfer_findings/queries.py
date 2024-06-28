from crum import get_current_user
from dojo.models import Product
from dojo.authorization.authorization import user_has_global_permission, user_has_permission 
from dojo.api_v2.api_error import ApiError
import logging
logger = logging.getLogger(__name__)


def get_products_for_transfer_findings(permission, user=None, product=None):
    if user is None:
        user = get_current_user()
    
    if user.is_superuser:
        return Product.objects.all().order_by('name')

    if user_has_global_permission(user, permission):
        return Product.objects.all().order_by('name')

    try:
        if product:
            if user_has_permission(user, product, permission):
                products = Product.objects.exclude(id=product.id)
            return products
        else:
            raise ApiError(detail="Current Product is None")

    except ApiError as e:
        logger.error(e)
        raise ApiError(e.message)
