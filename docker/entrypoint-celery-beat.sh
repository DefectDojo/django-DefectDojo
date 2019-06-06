#!/bin/sh

umask 0002

echo -n "Waiting for database to be reachable "
until echo "select 1;" | python3 manage.py dbshell > /dev/null
do
  echo -n "."
  sleep 1
done
echo

C_FORCE_ROOT=true exec celery \
  --app=dojo \
  beat \
  --pidfile=/run/celery-beat.pid
