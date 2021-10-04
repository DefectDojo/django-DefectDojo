from django.core.management.base import BaseCommand
from dojo.models import Test
from django.db.migrations.executor import MigrationExecutor
from django.db import connections, DEFAULT_DB_ALIAS

import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):

    help = 'Usage: manage.py fix_0120'

    def handle(self, *args, **options):
        connection = connections[DEFAULT_DB_ALIAS]
        connection.prepare_database()
        executor = MigrationExecutor(connection)
        dojo_last_mig = filter(lambda a: a[0] == 'dojo', executor.loader.graph.leaf_nodes()).__next__()[1]
        if dojo_last_mig == '0119_default_group_is_staff':
            logger.warning('This command will remove field "sonarqube_config" in model "Test" to be able to finish migration 0120_sonarqube_test_and_clean')
            try:
                schema_editor.remove_field(
                    model=Test,
                    field=Test._meta.get_field('sonarqube_config'),
                )
            except django.db.utils.OperationalError:
                # We expact exception like:
                #   django.db.utils.OperationalError: (1091, "Can't DROP 'sonarqube_config_id'; check that column/key exists")
                logger.info('Database fixed')
            else:
                logger.info('There was nothing to fix')
        else:
            logger.error('Only migrations stacked in front of 0119 can be fixed by this command')
