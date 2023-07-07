from django.core.management.base import BaseCommand
from django.db.models import Count

from dojo.models import Product, Product_Type, Tool_Type, JIRA_Issue

"""
Author: Aaron Weaver
This script will identify duplicates in DefectDojo:
"""

import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'No input commands for dedupe findings.'

    def count_the_duplicates(self, model, column):
        logger.debug("===================================")
        logger.debug(" Table:" + str(model) + " Column: " + column)
        logger.debug("===================================")
        duplicates = model.objects.values(column).annotate(Count('id')).order_by().filter(id__count__gt=1)
        kwargs = {'{0}__{1}'.format(column, 'in'): [item[column] for item in duplicates]}
        duplicates = model.objects.filter(**kwargs)

        if not duplicates:
            logger.debug("No duplicates found")
        for dupe in duplicates:
            logger.debug('{0}, Duplicate value: {1}, Object: {2}'.format(dupe.id, getattr(dupe, column), dupe))

    def handle(self, *args, **options):
        self.count_the_duplicates(Product, 'name')
        self.count_the_duplicates(Product_Type, 'name')
        self.count_the_duplicates(Tool_Type, 'name')
        self.count_the_duplicates(JIRA_Issue, 'jira_id')
