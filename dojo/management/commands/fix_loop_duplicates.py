from django.core.management.base import BaseCommand
from dojo.utils import fix_loop_duplicates

"""
Author: Marian Gawron
This script will identify loop dependencies in findings
"""


class Command(BaseCommand):
    help = 'No input commands for fixing Loop findings.'

    def handle(self, *args, **options):
        fix_loop_duplicates()
