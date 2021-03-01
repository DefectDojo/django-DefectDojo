#!/bin/sh

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

# Allow for bind-mount setting.py overrides
FILE=/app/docker/extra_settings/local_settings.py
if test -f "$FILE"; then
    echo "============================================================"
    echo "     Overriding DefectDojo's local_settings.py with $FILE."
    echo "============================================================"
    cp "$FILE" /app/dojo/settings/local_settings.py
fi

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

echo "Making migrations"
python3 manage.py makemigrations dojo
echo "Migrating"
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

if [ -z "${DD_JIRA_WEBHOOK_SECRET}" ]
then
  export DD_JIRA_WEBHOOK_SECRET="$(uuidgen)"
  echo "JIRA Webhook Secret: ${DD_JIRA_WEBHOOK_SECRET}"
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

  echo "Preparing survey fixture"
  # surveys fixture needs to be modified as it contains an instance dependant polymorphic content id
  python3 manage.py import_surveys
  # load surveys all at once as that's much faster
   echo "Importing fixtures all at once"
   python3 manage.py loaddata system_settings initial_banner_conf product_type test_type \
       development_environment benchmark_type benchmark_category benchmark_requirement \
       language_type objects_review regulation initial_surveys

  echo "UPDATE dojo_system_settings SET jira_webhook_secret='$DD_JIRA_WEBHOOK_SECRET'" | python manage.py dbshell

  echo "Importing extra fixtures"
  # If there is extra fixtures, load them
  for i in $(ls dojo/fixtures/extra_*.json | sort -n 2>/dev/null) ; do
    echo "Loading $i"
    python3 manage.py loaddata ${i%.*}
  done

  echo "Installing watson search index"
  python3 manage.py installwatson
fi
