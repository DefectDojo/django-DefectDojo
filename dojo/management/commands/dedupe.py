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
    help = 'Specific usage for dedupe command: manage.py dedupe [--parser "Parser1 Scan" --parser "Parser2 Scan"...] [--hash_code_only] [--dedupe_only]'

    def add_arguments(self, parser):
        parser.add_argument(
            '--parser',
            dest='parser',
            action='append',
            help='''List of parsers for which hash_code needs recomputing (defaults to all parsers)'''
        )

        parser.add_argument('--hash_code_only', action='store_true', help='Only compute hash codes')
        parser.add_argument('--dedupe_only', action='store_true', help='Only run deduplication')

    def handle(self, *args, **options):
        restrict_to_parsers = options['parser']
        hash_code_only = options['hash_code_only']
        dedupe_only = options['dedupe_only']

        if restrict_to_parsers is not None:
            logger.info("######## Will process only parsers %s ########", *restrict_to_parsers)
            # Get list of id from list of names (for optimisation)
            restrict_to_parsers_test_type = Test_Type.objects.filter(name__in=(restrict_to_parsers))
            restrict_to_parsers_test_type_id = list(
                map(
                    lambda test_type: test_type.id,
                    restrict_to_parsers_test_type))
            findings = Finding.objects.filter(test__test_type__id__in=(restrict_to_parsers_test_type_id)).order_by('-id')
        else:
            logger.info("######## Will process the full database ########")
            findings = Finding.objects.all().order_by('-id')

        # Phase 1: update hash_codes without deduplicating
        if not dedupe_only:
            for finding in findings:
                finding.hash_code = finding.compute_hash_code()
                finding.save(dedupe_option=False)
            logger.info("######## Done Updating Hashcodes########")

        # Phase 2: deduplicate synchronously
        if not hash_code_only:
            if get_system_setting('enable_deduplication'):
                for finding in findings:
                    from dojo.utils import do_dedupe_finding_sync
                    do_dedupe_finding_sync(finding)
                logger.info("######## Done deduplicating########")
            else:
                logger.debug("skipping dedupe because it's disabled in system settings")
