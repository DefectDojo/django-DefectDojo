#!/bin/sh

umask 0002

if [ "${DD_INITIALIZE}" = false ]
then
  echo "Echo initialization skipped. Exiting."
  exit
fi
echo "Initializing."

echo -n "Waiting for database to be reachable "
until echo "select 1;" | python3 manage.py dbshell > /dev/null
do
  echo -n "."
  sleep 1
done
echo

python3 manage.py makemigrations dojo
python3 manage.py migrate

echo "Admin user: ${DD_ADMIN_USER}"
ADMIN_EXISTS=$(echo "SELECT * from auth_user;" | python manage.py dbshell | grep "${DD_ADMIN_USER}")
# Abort if the admin user already exists, instead of giving a new fake password that won't work
if [ ! -z "$ADMIN_EXISTS" ]
then
    echo "Admin password: Initialization detected that the admin user ${DD_ADMIN_USER} already exists in your database."
    echo "If you don't remember the ${DD_ADMIN_USER} password, you can create a new superuser with:"
    echo "$ docker-compose exec uwsgi /bin/bash -c 'python manage.py createsuperuser'"
    exit
fi

if [ -z "${DD_ADMIN_PASSWORD}" ]
then
  export DD_ADMIN_PASSWORD="$(cat /dev/urandom | LC_ALL=C tr -dc a-zA-Z0-9 | \
    head -c 22)"
  echo "Admin password: ${DD_ADMIN_PASSWORD}"
fi

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

  python3 manage.py loaddata system_settings
  python3 manage.py loaddata initial_banner_conf
  python3 manage.py loaddata product_type
  python3 manage.py loaddata test_type
  python3 manage.py loaddata development_environment
  python3 manage.py loaddata benchmark_type
  python3 manage.py loaddata benchmark_category
  python3 manage.py loaddata benchmark_requirement
  python3 manage.py loaddata language_type
  python3 manage.py loaddata objects_review
  python3 manage.py loaddata regulation
  python3 manage.py import_surveys
  python3 manage.py loaddata initial_surveys
  python3 manage.py installwatson
  exec python3 manage.py buildwatson
fi
