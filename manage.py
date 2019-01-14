#!/usr/bin/env python
import os
import sys
from modify_modules import run_conversion

if __name__ == "__main__":
    run_conversion()

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dojo.settings.settings")

    from django.core.management import execute_from_command_line


    execute_from_command_line(sys.argv)

