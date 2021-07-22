"""
WSGI config for dojo project.

This module contains the WSGI application used by Django's development server
and any production WSGI deployments. It should expose a module-level variable
named ``application``. Django's ``runserver`` and ``runfcgi`` commands discover
this application via the ``WSGI_APPLICATION`` setting.

Usually you will have the standard Django WSGI application here, but it also
might make sense to replace the whole Django WSGI application with a custom one
that later delegates to the Django one. For example, you could introduce WSGI
middleware here, or combine a Django application with an application of another
framework.

"""
import os
import socket
import logging


logger = logging.getLogger(__name__)

# We defer to a DJANGO_SETTINGS_MODULE already in the environment. This breaks
# if running multiple sites in the same mod_wsgi process. To fix this, use
# mod_wsgi daemon mode with each site in its own daemon process, or use
# os.environ["DJANGO_SETTINGS_MODULE"] = "dojo.settings"
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dojo.settings.settings")


# Shouldn't apply to docker-compose dev mode (1 process, 1 thread), but may be needed when enabling debugging in other contexts
def is_debugger_listening(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return s.connect_ex(('127.0.0.1', port))


debugpy_port = os.environ.get("DD_DEBUG_PORT") if os.environ.get("DD_DEBUG_PORT") else 3000

# Checking for RUN_MAIN for those that want to run the app locally with the python interpreter instead of uwsgi
if os.environ.get("DD_DEBUG") == "True" and not os.getenv("RUN_MAIN") and is_debugger_listening(debugpy_port) != 0:
    logger.info("DD_DEBUG is set to True, setting remote debugging on port {}".format(debugpy_port))
    try:
        import debugpy

        # Required, otherwise debugpy will try to use the uwsgi binary as the python interpreter - https://github.com/microsoft/debugpy/issues/262
        debugpy.configure({
                            "python": "python",
                            "subProcess": True
                        })
        debugpy.listen(("0.0.0.0", debugpy_port))
        if os.environ.get("DD_DEBUG_WAIT_FOR_CLIENT") == "True":
            logger.info("Waiting for the debugging client to connect on port {}".format(debugpy_port))
            debugpy.wait_for_client()
            print("Debugging client connected, resuming execution")
    except Exception as e:
        logger.exception(e)
        pass

# This application object is used by any WSGI server configured to use this
# file. This includes Django's development server, if the WSGI_APPLICATION
# setting points here.
from django.core.wsgi import get_wsgi_application

application = get_wsgi_application()
