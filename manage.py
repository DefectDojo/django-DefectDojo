#!/usr/bin/env python
import os
import sys
from socket import error as socket_error
import socket


if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dojo.settings.settings")

    from django.core.management import execute_from_command_line

    def _check_ptvsd_port_not_in_use(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('127.0.0.1', port))
        except socket_error as se:
            return False

        return True

    # Enable ptvsd if running with DD_DEBUG
    ptvsd_port = 3000
    if os.environ.get("DD_DEBUG") == "on" and _check_ptvsd_port_not_in_use(ptvsd_port):
        try:
            # enable remote debugging
            import ptvsd
            ptvsd.enable_attach(address=('0.0.0.0', ptvsd_port))
        except Exception as e:
            print("Generic exception caught with DD_DEBUG on. Passing.")

    execute_from_command_line(sys.argv)
