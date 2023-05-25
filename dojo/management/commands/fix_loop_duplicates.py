from dojo.finding.helper import fix_loop_duplicates
from django.core.management.base import BaseCommand
import logging
logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


"""
Author: Marian Gawron
This script will identify loop dependencies in findings
"""


class Command(BaseCommand):
    help = 'No input commands for fixing Loop findings.'

    def handle(self, *args, **options):
        fix_loop_duplicates()
