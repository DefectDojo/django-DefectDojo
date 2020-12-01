# local_settings.py
# this file will be included by settings.py *after* loading settings.dist.py

from celery.schedules import crontab


CELERY_BEAT_SCHEDULE['auto-delete-engagements'] = {
    'task': 'dojo.tasks.auto_delete_engagements',
    'schedule': crontab(hour=9, minute=30)
}
