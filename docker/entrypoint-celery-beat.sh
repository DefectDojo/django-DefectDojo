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

exec celery beat \
  --app=dojo \
  --pidfile=/var/run/defectdojo/celery-beat.pid \
  --schedule=/var/run/defectdojo/celerybeat-schedule
