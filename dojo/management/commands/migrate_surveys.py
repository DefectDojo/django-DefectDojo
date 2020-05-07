from django.core.management.base import BaseCommand
from django.db import connection
import sys

"""
Author: Cody Maffucci
This script will migrate survey data from one external app to core dojo
"""


class Command(BaseCommand):
    help = 'import survey data from defectDojo_engagement_survey tables to dojo tables'

    def handle(self, *args, **options):
        # Get a connection to the db
        with connection.cursor() as cursor:
            # Check if there are any tables to migrate
            table_list = connection.introspection.table_names()
            survey_tables = [table for table in table_list if table.split('_')[0] == 'defectDojo']
            if len(survey_tables) == 0:
                sys.exit('There are no defectDojo_enagagement_survey tables to migrate.')

            # Copy the tables over
            for table in survey_tables:
                new_table_name = 'dojo' + table[21:]
                # Take all contents from ddse table and insert into dojo table
                copy_string = 'INSERT INTO ' + new_table_name + '* SELECT * FROM ' + table + ';'
                cursor.excute(copy_string)
                # Drop the ddse table
                cursor.execute('DROP' + table)
