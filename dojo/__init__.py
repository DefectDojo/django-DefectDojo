from __future__ import absolute_import

# This will make sure the app is always imported when
# Django starts so that shared_task will use this app.
from .celery import app as celery_app  # noqa

__version__ = '1.2.0'
__url__ = 'https://github.com/OWASP/django-DefectDojo'
__docs__ = 'https://defectdojo.readthedocs.io/'
__demo__ = 'https://defectdojo.pythonanywhere.com/'
