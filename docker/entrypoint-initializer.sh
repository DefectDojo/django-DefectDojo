#!/bin/sh

umask 0002

if [ "${DD_INITIALIZE}" = false ]
then
  echo "Echo initialization skipped. Exiting."
  exit
fi
echo "Initializing."

echo "Admin user: ${DD_ADMIN_USER}"

if [ -z "${DD_ADMIN_PASSWORD}" ]
then
  export DD_ADMIN_PASSWORD="$(cat /dev/urandom | LC_ALL=C tr -dc a-zA-Z0-9 | \
    head -c 22)"
  echo "Admin password: ${DD_ADMIN_PASSWORD}"
fi

echo -n "Waiting for database to be reachable "
until echo "select 1;" | python manage.py dbshell > /dev/null
do
  echo -n "."
  sleep 1
done
echo

python manage.py migrate

ADMIN_EXISTS=$(echo "SELECT * from auth_user;" | python manage.py dbshell | grep admin)

if [ -z "${ADMIN_EXISTS}" ]
then
cat <<EOD | python manage.py shell
import os
from django.contrib.auth.models import User
User.objects.create_superuser(
  os.getenv('DD_ADMIN_USER'),
  os.getenv('DD_ADMIN_MAIL'),
  os.getenv('DD_ADMIN_PASSWORD'),
  first_name=os.getenv('DD_ADMIN_FIRST_NAME'),
  last_name=os.getenv('DD_ADMIN_LAST_NAME')
)
EOD

  python manage.py loaddata product_type
  python manage.py loaddata test_type
  python manage.py loaddata development_environment
  python manage.py loaddata system_settings
  python manage.py loaddata benchmark_type
  python manage.py loaddata benchmark_category
  python manage.py loaddata benchmark_requirement
  python manage.py loaddata language_type
  python manage.py loaddata objects_review
  python manage.py loaddata regulation
  python manage.py installwatson
  exec python manage.py buildwatson
fi
