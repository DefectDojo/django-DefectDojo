import logging
from django.conf import settings
from django.core.management.base import BaseCommand
from dojo.models import Dojo_User, Global_Role, Role, Product, Product_Member, Product_Type, Product_Type_Member
from dojo.authorization.roles_permissions import Roles


logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    This management command migrated authorized users of product types and
    products to product type members and product members. Since the legacy
    authorization is removed from the code now, this management command is
    empty. It cannot be removed because it is called in a db migration.
    """
    help = 'Usage: manage.py migration_authorization_v2'

    def handle(self, *args, **options):
        pass
