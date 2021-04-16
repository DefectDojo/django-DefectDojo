import json
from django.core.management.base import BaseCommand
from dojo.tools import factory
from dojo.models import  Tool_Type


class Command(BaseCommand):
    """
        Dumps json file of supported scanners or directly re-sync it to the DB
        this is quick and dirty, TODO: refactor
        """

    def add_arguments(self, parser):
        parser.add_argument('-f','--file_path', required=False)
        parser.add_argument('-r', '--resync', action='store_true')

    def handle(self, *args, **options):
        counter = 30
        model = "dojo.Tool_Type"
        dump = []
        for parser in factory.PARSERS:
            dump.append(
                {'model': model,
                 'pk': counter,
                 'fields': {
                     'name': factory.PARSERS[parser].get_scan_types()[0],
                     'description': factory.PARSERS[parser].get_description_for_scan_types("mock")
                 }
                 }
            )
            if options['resync']:
                try:
                    print('Sync {0}'.format(factory.PARSERS[parser].get_scan_types()[0]))
                    scanner = Tool_Type.objects.get_or_create(name = factory.PARSERS[parser].get_scan_types()[0], description = factory.PARSERS[parser].get_description_for_scan_types("mock"))

                except Exception as e:
                    print(e)

            counter += 1
        if options['file_path']:
            file = open(options['file_path'], "a")
            file.write(json.dumps(dump))
            file.close()
