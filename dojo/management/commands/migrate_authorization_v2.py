import logging
from django.core.management.base import BaseCommand


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
