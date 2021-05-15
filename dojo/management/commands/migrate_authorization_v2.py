import logging
from django.conf import settings
from django.core.management.base import BaseCommand
from dojo.models import Dojo_User, Product, Product_Member, Product_Type, Product_Type_Member
from dojo.authorization.roles_permissions import Roles


logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    When changing to authorization v2, this command adds staff users and
    authorized users as product type members / product members according
    to their permissions they have had before and the settings.
    """
    help = 'Usage: manage.py migration_authorization_v2'

    def handle(self, *args, **options):

        logger.info('Started migrating users for authorization v2 ...')

        authorized_user_exists = False

        product_types = Product_Type.objects.all().prefetch_related('authorized_users')
        staff_users = Dojo_User.objects.filter(is_staff=True, is_superuser=False)
        for product_type in product_types:
            # Staff users have had all permissions for all product types and products,
            # so they will be set as owners for all product types.
            # Superusers will have all permissions anyway, so they must not be set as members.
            for staff_user in staff_users:
                # If the product type member already exists, it won't be changed
                if Product_Type_Member.objects.filter(product_type=product_type, user=staff_user).count() == 0:
                    product_type_member = Product_Type_Member()
                    product_type_member.product_type = product_type
                    product_type_member.user = staff_user
                    product_type_member.role = 4  # Owner
                    product_type_member.save()
                    logger.info('Product_Type_Member added: {} / {} / {}'.format(product_type.name, staff_user.username, Roles(product_type_member.role).name))
                else:
                    logger.info('Product_Type_Member already exists: {} / {}'.format(product_type.name, staff_user.username))

            # Authorized users for product types will be converted to product type members
            # with a role according to the settings
            for authorized_user in product_type.authorized_users.all():
                # If the product type member already exists, it won't be changed
                if Product_Type_Member.objects.filter(product_type=product_type, user=authorized_user).count() == 0:
                    authorized_user_exists = True
                    product_type_member = Product_Type_Member()
                    product_type_member.product_type = product_type
                    product_type_member.user = authorized_user
                    product_type_member.role = get_role()
                    product_type_member.save()
                    logger.info('Product_Type_Member added: {} / {} / {}'.format(product_type.name, authorized_user.username, Roles(product_type_member.role).name))
                else:
                    logger.info('Product_Type_Member already exists: {} / {}'.format(product_type.name, authorized_user.username))

        products = Product.objects.all().prefetch_related('authorized_users')
        for product in products:
            # Authorized users for products will be converted to product members
            # with a role according to the settings
            for authorized_user in product.authorized_users.all():
                # If the product member already exists, it won't be changed
                if Product_Member.objects.filter(product=product, user=authorized_user).count() == 0:
                    authorized_user_exists = True
                    product_member = Product_Member()
                    product_member.product = product
                    product_member.user = authorized_user
                    product_member.role = get_role()
                    product_member.save()
                    logger.info('Product_Member added: {} / {} / {}'.format(product.name, authorized_user.username, Roles(product_member.role).name))
                else:
                    logger.info('Product_Member already exists: {} / {}'.format(product.name, authorized_user.username))

        if authorized_user_exists and not settings.AUTHORIZED_USERS_ALLOW_STAFF and \
                (settings.AUTHORIZED_USERS_ALLOW_CHANGE or settings.AUTHORIZED_USERS_ALLOW_DELETE):
            logger.warn('Authorized users have more permissions than before, because there is no equivalent for AUTHORIZED_USERS_ALLOW_CHANGE and AUTHORIZED_USERS_ALLOW_DELETE')

        logger.info('Finished migrating users for authorization v2')


def get_role():
    if settings.AUTHORIZED_USERS_ALLOW_STAFF:
        return 4  # Owner
    elif settings.AUTHORIZED_USERS_ALLOW_CHANGE or settings.AUTHORIZED_USERS_ALLOW_DELETE:
        return 2  # Writer
    else:
        return 0  # Reader
