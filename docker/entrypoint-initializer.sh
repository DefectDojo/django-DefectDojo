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
until echo "select 1;" | python3 manage.py dbshell > /dev/null
do
  echo -n "."
  sleep 1
done
echo

python3 manage.py makemigrations dojo
python3 manage.py migrate

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

  python3 manage.py loaddata product_type
  python3 manage.py loaddata test_type
  python3 manage.py loaddata development_environment
  python3 manage.py loaddata system_settings
  python3 manage.py loaddata benchmark_type
  python3 manage.py loaddata benchmark_category
  python3 manage.py loaddata benchmark_requirement
  python3 manage.py loaddata language_type
  python3 manage.py loaddata objects_review
  python3 manage.py loaddata regulation
  python3 manage.py installwatson
  exec python3 manage.py buildwatson
fi
