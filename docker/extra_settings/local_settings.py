# local_settings.py
# this file will be included by settings.py *after* loading settings.dist.py

from celery.schedules import crontab

# add our own cb_tasks.py for tasks to get registered
CELERY_IMPORTS = ('dojo.cb_tasks')
CELERY_BEAT_SCHEDULE['auto-delete-engagements'] = {
    'task': 'dojo.cb_tasks.auto_delete_engagements',
    'schedule': crontab(hour=9, minute=30)
}

# Override deduplication for certain parsers
HASHCODE_FIELDS_PER_SCANNER['Anchore Engine Scan'] = ['title', 'severity', 'component_name', 'component_version']
HASHCODE_ALLOWS_NULL_CWE['Anchore Engine Scan'] = True
DEDUPLICATION_ALGORITHM_PER_PARSER['Anchore Engine Scan'] = DEDUPE_ALGO_HASH_CODE

HASHCODE_FIELDS_PER_SCANNER['Twistlock Image Scan'] = ['title', 'severity', 'component_name', 'component_version']
HASHCODE_ALLOWS_NULL_CWE['Twistlock Image Scan'] = True
DEDUPLICATION_ALGORITHM_PER_PARSER['Twistlock Image Scan'] = DEDUPE_ALGO_HASH_CODE

# HASHCODE_FIELDS_PER_SCANNER['Dependency Check Scan'] = ['title', 'severity', 'component_name', 'component_version']
# HASHCODE_ALLOWS_NULL_CWE['Dependency Check Scan'] = True
# DEDUPLICATION_ALGORITHM_PER_PARSER['Dependency Check Scan'] = DEDUPE_ALGO_HASH_CODE
