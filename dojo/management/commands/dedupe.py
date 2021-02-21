from django.core.management.base import BaseCommand
from pytz import timezone

from dojo.models import Finding, Test_Type
from dojo.utils import get_system_setting
import logging

locale = timezone(get_system_setting('time_zone'))

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")

"""
Author: Aaron Weaver
This script will update the hashcode and dedupe findings in DefectDojo:
"""


class Command(BaseCommand):
    help = 'Specific usage for dedupe command: manage.py dedupe [--parser "Parser1 Scan" --parser "Parser2 Scan"...]'

    def add_arguments(self, parser):
        parser.add_argument(
            '--parser',
            dest='parser',
            action='append',
            help='''List of parsers for which hash_code needs recomputing (defaults to all parsers)'''
        )

    def handle(self, *args, **options):
        restrict_to_parsers = options['parser']
        if restrict_to_parsers is not None:
            logger.info("######## Updating Hashcodes for parsers %s ########", *restrict_to_parsers)
            # Get list of id from list of names (for optimisation)
            restrict_to_parsers_test_type = Test_Type.objects.filter(name__in=(restrict_to_parsers))
            restrict_to_parsers_test_type_id = list(
                map(
                    lambda test_type: test_type.id,
                    restrict_to_parsers_test_type))
            findings = Finding.objects.filter(test__test_type__id__in=(restrict_to_parsers_test_type_id))
        else:
            logger.info("######## Updating Hashcodes for the full database ########")
            findings = Finding.objects.all()
        for finding in findings:
            finding.hash_code = finding.compute_hash_code()
            finding.save()
        logger.info("######## Done Updating Hashcodes (deduplication is done in the background  upon finding save)########")
