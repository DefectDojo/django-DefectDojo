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

# Allow for bind-mount multiple settings.py overrides
FILES=$(ls -I README.md /app/docker/extra_settings)
NUM_FILES=$(echo "$FILES" | wc -l)
if [ "$NUM_FILES" -gt "1" ]; then
    COMMA_LIST=$(echo $FILES | tr -s '[:blank:]' ', ')
    echo "============================================================"
    echo "     Overriding DefectDojo's local_settings.py with multiple"
    echo "     Files: $COMMA_LIST"
    echo "============================================================"
    cp /app/docker/extra_settings/* /app/dojo/settings/
fi

if [ "${DD_CELERY_WORKER_POOL_TYPE}" = "prefork" ]; then
  EXTRA_PARAMS="--autoscale=${DD_CELERY_WORKER_AUTOSCALE_MAX},${DD_CELERY_WORKER_AUTOSCALE_MIN}
    --prefetch-multiplier=${DD_CELERY_WORKER_PREFETCH_MULTIPLIER}"
fi

# do the check with Django stack
python3 manage.py check

exec celery --app=dojo \
    worker \
  --loglevel="${DD_CELERY_LOG_LEVEL}" \
  --pool="${DD_CELERY_WORKER_POOL_TYPE}" \
  --concurrency=${DD_CELERY_WORKER_CONCURRENCY:-1} \
  ${EXTRA_PARAMS}

