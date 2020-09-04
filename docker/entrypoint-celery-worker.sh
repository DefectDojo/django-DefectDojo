#!/bin/sh
set -x
umask 0002

id

echo -n "Waiting for database to be reachable "
until echo "select 1;" | python3 manage.py dbshell > /dev/null
do
  echo -n "."
  sleep 1
done
echo

exec celery worker \
    --app=dojo \
    --loglevel="${DD_CELERY_LOG_LEVEL}" \
    --pool=solo \
    --concurrency=1
