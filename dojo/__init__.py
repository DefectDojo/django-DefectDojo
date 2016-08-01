from __future__ import absolute_import

# This will make sure the app is always imported when
# Django starts so that shared_task will use this app.
from .celery import app as celery_app  # noqa

__version__ = '1.0.5'
__url__ = 'https://github.com/rackerlabs/django-DefectDojo'
__docs__ = 'http://defectdojo.readthedocs.io/'
__demo__ = 'http://defectdojo.pythonanywhere.com/'
