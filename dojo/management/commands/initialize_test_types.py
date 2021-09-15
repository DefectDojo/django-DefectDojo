from django.core.management.base import BaseCommand
from dojo.tools.factory import initialize_test_types


class Command(BaseCommand):
    help = 'Initializes Test_Types'

    def handle(self, *args, **options):
        initialize_test_types()
