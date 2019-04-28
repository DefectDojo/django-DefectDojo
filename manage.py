#!/usr/bin/env python
import os
import sys


if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dojo.settings.settings")

    from django.core.management import execute_from_command_line

    if os.environ.get("DD_DEBUG") == "on":
        try:
            # enable remote debugging
            import ptvsd
            ptvsd.enable_attach(address=('0.0.0.0', 3000), redirect_output=True)
        except Exception as e:
            pass

    execute_from_command_line(sys.argv)
