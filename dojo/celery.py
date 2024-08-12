import logging
import os

from celery import Celery
from celery.signals import setup_logging, beat_init, worker_ready, worker_shutdown, after_task_publish
from django.conf import settings
from pathlib import Path
from dojo.bootstraps import LivenessProbe
import logging

logger = logging.getLogger(__name__)

# File for validating worker readiness
READINESS_FILE = Path('/tmp/celery_ready')
# File for validating beat liveness
HEARTBEAT_FILE = Path('/tmp/celery_live')

# set the default Django settings module for the 'celery' program.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dojo.settings.settings")

app = Celery("dojo")

# Using a string here means the worker will not have to
# pickle the object when using Windows.
app.config_from_object("django.conf:settings", namespace="CELERY")

app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)

# celery worker liveness check
app.steps["worker"].add(LivenessProbe)

@app.task(bind=True)
def debug_task(self):
    logger.info(f"Request: {self.request!r}")


@setup_logging.connect
def config_loggers(*args, **kwags):
    from logging.config import dictConfig
    dictConfig(settings.LOGGING)


# celery worker readiness check

@worker_ready.connect
def worker_ready(**_):
    READINESS_FILE.touch()

@worker_shutdown.connect
def worker_shutdown(**_):
    READINESS_FILE.unlink(missing_ok=True)

# celery beat readiness and liveness checks

@beat_init.connect
def beat_ready(**_):
    READINESS_FILE.touch()

@after_task_publish.connect
def task_published(**_):
    HEARTBEAT_FILE.touch()

# from celery import current_app

# _ = current_app.loader.import_default_modules()

# tasks = list(sorted(name for name in current_app.tasks
#                             if not name.startswith('celery.')))

# logger.debug('registered celery tasks:')
# for task in tasks:
#     logger.debug(task)
