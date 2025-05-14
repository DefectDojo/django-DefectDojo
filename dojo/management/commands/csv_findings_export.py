import csv
from pathlib import Path

from django.core.management.base import BaseCommand
from pytz import timezone

from dojo.models import Finding
from dojo.utils import get_system_setting

locale = timezone(get_system_setting("time_zone"))

"""
Author: Aaron Weaver
This script will extract all verified and active findings
"""


class Command(BaseCommand):
    help = "Input: Filepath and name"

    def add_arguments(self, parser):
        parser.add_argument("file_path")

    def handle(self, *args, **options):
        file_path = Path(options["file_path"])

        findings = Finding.objects.filter(verified=True,
                                          active=True).select_related(
            "test__engagement__product")
        writer = csv.writer(file_path.open("w", encoding="utf-8"))

        headers = [
            "product_name",
            "id",
            "title",
            "cwe",
            "date",
            "url",
            "severity",
        ]

        # for field in opts.fields:
        #    headers.append(field.name)

        writer.writerow(headers)
        for obj in findings:
            row = []
            row.append(obj.test.engagement.product)
            for field in headers:
                if field != "product_name":
                    value = getattr(obj, field)
                    if isinstance(value, str):
                        value = value.encode("utf-8").strip()

                    row.append(value)
            writer.writerow(row)
