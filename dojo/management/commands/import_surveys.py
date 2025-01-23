from pathlib import Path

from django.core.management.base import BaseCommand
from django.db import connection
from pytz import timezone

from dojo.models import TextQuestion
from dojo.utils import get_system_setting

locale = timezone(get_system_setting("time_zone"))

"""
Author: Cody Maffucci
This script will import initial surverys and questions into DefectDojo:
"""


class Command(BaseCommand):
    help = "Import surverys from dojo/fixtures/initial_surveys.py"

    def handle(self, *args, **options):
        # First create a temp question to pull the polymorphic_ctype_id from
        created_question = TextQuestion.objects.create(optional=False, order=1, text="What is love?")
        # Get the ID used in this system
        with connection.cursor() as cursor:
            cursor.execute("select polymorphic_ctype_id from dojo_question;")
            row = cursor.fetchone()
            ctype_id = row[0]
        # Find the current id in the surveys file
        path = Path(__file__).parent.absolute()
        path = path[:-19] + "fixtures/initial_surveys.json"
        contents = open(path, encoding="utf-8").readlines()
        for line in contents:
            if '"polymorphic_ctype": ' in line:
                matchedLine = line
                break
        # Create the new id line
        old_id = "".join(c for c in matchedLine if c.isdigit())
        new_line = matchedLine.replace(old_id, str(ctype_id))
        # Replace the all lines in the file
        with open(path, "w", encoding="utf-8") as fout:
            fout.writelines(line.replace(matchedLine, new_line) for line in contents)
        # Delete the temp question
        created_question.delete()
