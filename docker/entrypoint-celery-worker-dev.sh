#!/bin/bash
umask 0002

id

set -e  # needed to handle "exit" correctly

. /secret-file-loader.sh
. /reach_database.sh

wait_for_database_to_be_reachable
echo

if [ "${DD_CELERY_WORKER_POOL_TYPE}" = "prefork" ]; then
  EXTRA_PARAMS=("--autoscale=${DD_CELERY_WORKER_AUTOSCALE_MAX},${DD_CELERY_WORKER_AUTOSCALE_MIN}"
    "--prefetch-multiplier=${DD_CELERY_WORKER_PREFETCH_MULTIPLIER}")
else
  EXTRA_PARAMS=()
fi

# do the check with Django stack
python3 manage.py check

# hot reload using watmedo as we don't want to install celery[dev] and have that end up in our production images
watchmedo auto-restart --directory=./ --pattern="*.py;*.tpl" --recursive -- \
  celery --app=dojo worker --loglevel="${DD_CELERY_LOG_LEVEL}" --pool="${DD_CELERY_WORKER_POOL_TYPE}" --concurrency="${DD_CELERY_WORKER_CONCURRENCY:-1}" "${EXTRA_PARAMS[@]}"
