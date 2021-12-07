from django.conf import settings
import logging
from dojo.models import Finding, Finding_Group, Test, Engagement, Product, Endpoint, Product_Type, \
    Risk_Acceptance

logger = logging.getLogger(__name__)


def check_auth_users_list(user, obj):
    is_authorized = False
    if isinstance(obj, Product_Type):
        is_authorized = user in obj.authorized_users.all()
        if not is_authorized:
            products = obj.prod_type.all()
            for product in products:
                is_authorized = is_authorized or user in product.authorized_users.all()
    elif isinstance(obj, Finding):
        is_authorized = user in obj.test.engagement.product.authorized_users.all()
        is_authorized = user in obj.test.engagement.product.prod_type.authorized_users.all() or is_authorized
    elif isinstance(obj, Finding_Group):
        return check_auth_users_list(obj.test)
    elif isinstance(obj, Test):
        is_authorized = user in obj.engagement.product.authorized_users.all()
        is_authorized = user in obj.engagement.product.prod_type.authorized_users.all() or is_authorized
    elif isinstance(obj, Engagement):
        is_authorized = user in obj.product.authorized_users.all()
        is_authorized = user in obj.product.prod_type.authorized_users.all() or is_authorized
    elif isinstance(obj, Product):
        is_authorized = user in obj.authorized_users.all()
        is_authorized = user in obj.prod_type.authorized_users.all() or is_authorized
    elif isinstance(obj, Endpoint):
        is_authorized = user in obj.product.authorized_users.all()
        is_authorized = user in obj.product.prod_type.authorized_users.all() or is_authorized
    elif isinstance(obj, Risk_Acceptance):
        return user.username == obj.owner.username or check_auth_users_list(user, obj.engagement_set.all()[0])
    else:
        raise ValueError('invalid obj %s to check for permissions' % obj)

    return is_authorized


def user_is_authorized(user, perm_type, obj):
    # print('help.user_is_authorized')
    # print('user: ', user.id)
    # print('perm_type', perm_type)
    # print('obj: ', obj)

    if perm_type not in ['view', 'change', 'delete', 'staff']:
        logger.error('permtype %s not supported', perm_type)
        raise ValueError('permtype ' + perm_type + ' not supported')

    if user.is_staff:
        # print('is_staff, returning True')
        return True

    # Risk Acceptance owner has always permission
    if isinstance(obj, Risk_Acceptance):
        if user.username == obj.owner.username:
            return True

    authorized_staff = settings.AUTHORIZED_USERS_ALLOW_STAFF

    if perm_type == 'staff' and not authorized_staff:
        return user.is_staff or user.is_superuser

    if perm_type == 'change' and not settings.AUTHORIZED_USERS_ALLOW_CHANGE and not authorized_staff:
        return user.is_staff or user.is_superuser

    if perm_type == 'delete' and not settings.AUTHORIZED_USERS_ALLOW_DELETE and not authorized_staff:
        return user.is_staff or user.is_superuser

    # at this point being in the authorized users lists means permission should be granted
    return check_auth_users_list(user, obj)
