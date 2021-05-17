#!/bin/sh
umask 0002

id

echo -n "Waiting for database to be reachable "
until echo "select 1;" | python3 manage.py dbshell > /dev/null
do
  echo -n "."
  sleep 1
done
echo

# Allow for bind-mount setting.py overrides
FILE=/app/docker/extra_settings/settings.dist.py
if test -f "$FILE"; then
    echo "============================================================"
    echo "     Overriding DefectDojo's settings.dist.py with $FILE."
    echo "============================================================"
    cp "$FILE" /app/dojo/settings/settings.dist.py
fi

# Allow for bind-mount setting.py overrides
FILE=/app/docker/extra_settings/settings.py
if test -f "$FILE"; then
    echo "============================================================"
    echo "     Overriding DefectDojo's settings.py with $FILE."
    echo "============================================================"
    cp "$FILE" /app/dojo/settings/settings.py
fi

FILE=/app/docker/extra_settings/local_settings.py
if test -f "$FILE"; then
    echo "============================================================"
    echo "     Overriding DefectDojo's local_settings.py with $FILE."
    echo "============================================================"
    cp "$FILE" /app/dojo/settings/local_settings.py
fi

if [ "${DD_CELERY_WORKER_POOL_TYPE}" = "prefork" ]; then
  EXTRA_PARAMS="--autoscale=${DD_CELERY_WORKER_AUTOSCALE_MAX},${DD_CELERY_WORKER_AUTOSCALE_MIN}
    --prefetch-multiplier=${DD_CELERY_WORKER_PREFETCH_MULTIPLIER}"
fi

exec celery worker \
  --app=dojo \
  --loglevel="${DD_CELERY_LOG_LEVEL}" \
  --pool="${DD_CELERY_WORKER_POOL_TYPE}" \
  --concurrency=${DD_CELERY_WORKER_CONCURRENCY:-1} \
  ${EXTRA_PARAMS}
