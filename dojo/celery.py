from __future__ import absolute_import
import os
from celery import Celery
from celery.schedules import crontab
from django.conf import settings

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dojo.settings')

app = Celery('dojo')

# Using a string here means the worker will not have to
# pickle the object when using Windows.
app.config_from_object('django.conf:settings')

app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)


@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))

"""
@app.on_after_configure.connect
def setup_periodic_tasks(sender, *args, **kwargs):
    from dojo.tasks import async_dupe_delete
    sender.add_periodic_task(crontab(hours=0,minutes=0), async_dupe_delete(*args, **kwargs) )
"""
app.conf.beat_schedule = {
    # Executes every Monday morning at 7:30 a.m.
    'add-every-monday-morning': {
        'task': 'dojo.tasks.async_dupe_delete',
        'schedule': 30.0,
        'args': (16, 16),
    },
}
