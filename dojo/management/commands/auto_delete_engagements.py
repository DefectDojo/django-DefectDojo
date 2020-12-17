from django.core.management.base import BaseCommand
from dojo.cb_utils import auto_delete_engagements

"""
This command will iterate over engagements and delete them if they match required criteria
"""


class Command(BaseCommand):
    help = 'Launch with no argument.'

    def handle(self, *args, **options):
        auto_delete_engagements()
