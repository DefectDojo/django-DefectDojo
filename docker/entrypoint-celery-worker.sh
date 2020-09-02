#!/bin/sh

umask 0002

echo -n "Waiting for database to be reachable "
until echo "select 1;" | python3 manage.py dbshell > /dev/null
do
  echo -n "."
  sleep 1
done
echo

if [ "${DD_CELERY_WORKER_POOL_TYPE}" = "prefork" ]; then
  EXTRA_PARAMS="--autoscale=${DD_CELERY_WORKER_AUTOSCALE_MAX},${DD_CELERY_WORKER_AUTOSCALE_MIN}
    --prefetch-multiplier=${DD_CELERY_WORKER_PREFETCH_MULTIPLIER}"
fi

C_FORCE_ROOT=true exec celery \
  --app=dojo \
  worker \
  --loglevel="${DD_CELERY_LOG_LEVEL}" \
  --pool="${DD_CELERY_WORKER_POOL_TYPE}" \
  --concurrency=${DD_CELERY_WORKER_CONCURRENCY:-1} \
  ${EXTRA_PARAMS}
