

# This will make sure the app is always imported when
# Django starts so that shared_task will use this app.
from .celery import app as celery_app  # noqa

__version__ = '2.8.0'
__url__ = 'https://github.com/DefectDojo/django-DefectDojo'
__docs__ = 'https://defectdojo.github.io/django-DefectDojo'
