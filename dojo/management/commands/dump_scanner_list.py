import json
from django.core.management.base import BaseCommand
from dojo.tools import factory

##This just helped to create JSON fixtures

class Command(BaseCommand):
        """
        Dumps json file of supported scanners
        """
        counter = 1
        model = "dojo.Tool_Type"
        dump = []
        for parser in factory.PARSERS:
          dump.append(
              {   'model': model,
                  'pk': counter,
                  'fields': {
                      'name': factory.PARSERS[parser].get_scan_types()[0],
                      'description': factory.PARSERS[parser].get_description_for_scan_types("mock")
                  }
              }
          )
          counter+=1
        print(json.dumps(dump))