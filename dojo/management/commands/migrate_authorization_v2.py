import logging
from django.conf import settings
from django.core.management.base import BaseCommand
from dojo.models import Dojo_User, Global_Role, Role, Product, Product_Member, Product_Type, Product_Type_Member
from dojo.authorization.roles_permissions import Roles


logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    When changing to authorization v2, this command adds staff users and
    authorized users as product type members / product members according
    to their permissions they have had before and the settings.
    """
    help = 'Usage: manage.py migration_authorization_v2'

    def __init__(self, **kwargs):
        self.reader_role = Role.objects.get(id=Roles.Reader)
        self.writer_role = Role.objects.get(id=Roles.Writer)
        self.owner_role = Role.objects.get(id=Roles.Owner)

    def handle(self, *args, **options):
        logger.info('Started migrating users for authorization v2 ...')

        authorized_user_exists = False

        # Staff users have had all permissions for all product types and products,
        # so they will be get a global role as Owner.
        # Superusers will have all permissions anyway, so they must not be set as members.
        staff_users = Dojo_User.objects.filter(is_staff=True, is_superuser=False)
        for staff_user in staff_users:
            global_role = staff_user.global_role if hasattr(staff_user, 'global_role') else None
            if global_role is None:
                global_role = Global_Role()
                global_role.user = staff_user
            if global_role.role is None:
                global_role.role = self.owner_role
                global_role.save()
                logger.info('Global_Role Owner added for staff user {}'.format(staff_user))
            else:
                logger.info('Staff user {} already has Global_Role {}'.format(staff_user, global_role.role))

        # Authorized users for product types will be converted to product type members
        # with a role according to the settings
        product_types = Product_Type.objects.all().prefetch_related('authorized_users')
        for product_type in product_types:
            for authorized_user in product_type.authorized_users.all():
                # If the product type member already exists, it won't be changed
                if Product_Type_Member.objects.filter(product_type=product_type, user=authorized_user).count() == 0:
                    authorized_user_exists = True
                    product_type_member = Product_Type_Member()
                    product_type_member.product_type = product_type
                    product_type_member.user = authorized_user
                    product_type_member.role = self.get_role()
                    product_type_member.save()
                    logger.info('Product_Type_Member added: {} / {} / {}'.format(product_type, authorized_user, product_type_member.role))
                else:
                    logger.info('Product_Type_Member already exists: {} / {}'.format(product_type, authorized_user))

        # Authorized users for products will be converted to product members
        # with a role according to the settings
        products = Product.objects.all().prefetch_related('authorized_users')
        for product in products:
            for authorized_user in product.authorized_users.all():
                # If the product member already exists, it won't be changed
                if Product_Member.objects.filter(product=product, user=authorized_user).count() == 0:
                    authorized_user_exists = True
                    product_member = Product_Member()
                    product_member.product = product
                    product_member.user = authorized_user
                    product_member.role = self.get_role()
                    product_member.save()
                    logger.info('Product_Member added: {} / {} / {}'.format(product, authorized_user, product_member.role))
                else:
                    logger.info('Product_Member already exists: {} / {}'.format(product, authorized_user))

        if authorized_user_exists and not settings.AUTHORIZED_USERS_ALLOW_STAFF and \
                (settings.AUTHORIZED_USERS_ALLOW_CHANGE or settings.AUTHORIZED_USERS_ALLOW_DELETE):
            logger.warn('Authorized users have more permissions than before, because there is no equivalent for AUTHORIZED_USERS_ALLOW_CHANGE and AUTHORIZED_USERS_ALLOW_DELETE')

        logger.info('Finished migrating users for authorization v2')

    def get_role(self):
        if settings.AUTHORIZED_USERS_ALLOW_STAFF:
            return self.owner_role
        elif settings.AUTHORIZED_USERS_ALLOW_CHANGE or settings.AUTHORIZED_USERS_ALLOW_DELETE:
            return self.writer_role
        else:
            return self.reader_role
