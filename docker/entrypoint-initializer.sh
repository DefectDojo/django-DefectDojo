#!/bin/sh

initialize_data()
{
    # Test types shall be initialized every time by the initializer, to make sure test types are complete
    # when new parsers have been implemented
    echo "Initialization of test_types"
    python3 manage.py initialize_test_types

    # Non-standard permissions cannot be created with a database migration, because the content type will only
    # be available after the dojo migrations
    echo "Creation of non-standard permissions"
    python3 manage.py initialize_permissions
}

# Allow for bind-mount multiple settings.py overrides
FILES=$(ls /app/docker/extra_settings/* 2>/dev/null)
NUM_FILES=$(echo "$FILES" | wc -w)
if [ "$NUM_FILES" -gt 0 ]; then
    COMMA_LIST=$(echo $FILES | tr -s '[:blank:]' ', ')
    echo "============================================================"
    echo "     Overriding DefectDojo's local_settings.py with multiple"
    echo "     Files: $COMMA_LIST"
    echo "============================================================"
    cp /app/docker/extra_settings/* /app/dojo/settings/
    rm -f /app/dojo/settings/README.md
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
    initialize_data
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

  # load surveys all at once as that's much faster
   echo "Importing fixtures all at once"
   python3 manage.py loaddata system_settings initial_banner_conf product_type test_type \
       development_environment benchmark_type benchmark_category benchmark_requirement \
       language_type objects_review regulation initial_surveys role

  echo "UPDATE dojo_system_settings SET jira_webhook_secret='$DD_JIRA_WEBHOOK_SECRET'" | python manage.py dbshell

  echo "Importing extra fixtures"
  # If there is extra fixtures, load them
  for i in $(ls dojo/fixtures/extra_*.json | sort -n 2>/dev/null) ; do
    echo "Loading $i"
    python3 manage.py loaddata ${i%.*}
  done

  echo "Installing watson search index"
  python3 manage.py installwatson

  # surveys fixture needs to be modified as it contains an instance dependant polymorphic content id
  echo "Migration of textquestions for surveys"
  python3 manage.py migrate_textquestions

  initialize_data

fi
