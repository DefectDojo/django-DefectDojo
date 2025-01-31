#!/bin/bash

. /secret-file-loader.sh
. /reach_database.sh

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

create_announcement_banner() 
{
# Load the announcement banner
if [ -z "$DD_CREATE_CLOUD_BANNER" ]; then
echo "Creating Announcement Banner"
cat <<EOD | python3 manage.py shell
from dojo.models import Announcement, UserAnnouncement, Dojo_User
announcement, created = Announcement.objects.get_or_create(id=1)
announcement.message = '<a href="https://defectdojo.com/contact" target="_blank">Cloud and On-Premise Subscriptions Now Available! Click here for more details</a>'
announcement.dismissable = True
announcement.save()
for dojo_user in Dojo_User.objects.all():
    user_announcments = UserAnnouncement.objects.filter(
        user=dojo_user,
        announcement=announcement)
    if user_announcments.count() == 0:
        UserAnnouncement.objects.get_or_create(
            user=dojo_user,
            announcement=announcement)
EOD
fi
}

# Allow for bind-mount multiple settings.py overrides
FILES=$(ls /app/docker/extra_settings/* 2>/dev/null)
NUM_FILES=$(echo "$FILES" | wc -w)
if [ "$NUM_FILES" -gt 0 ]; then
    COMMA_LIST=$(echo "$FILES" | tr -s '[:blank:]' ', ')
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

wait_for_database_to_be_reachable
echo

echo "Checking ENABLE_AUDITLOG"
cat <<EOD | if ! python manage.py shell
from django.db import connections, DEFAULT_DB_ALIAS
from django.db.utils import ProgrammingError
from dojo.settings import settings
def dictfetchall(cursor):
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]
with connections[DEFAULT_DB_ALIAS].cursor() as c:
    try:
        c.execute('select * from dojo_system_settings limit 1')
    except ProgrammingError as e:
        err_msg = str(e)
        if "does not exist" in err_msg or "doesn't exist" in err_msg:
            print('Django has not been initialized. Nothing to check.')
            exit(0)
        else:
            raise
    raw_row = dictfetchall(c)[0]
if 'enable_auditlog' in raw_row:  # db is not migrated yet
    print("Database has not been migrated yet. Good we can check the latest values.")
    if not raw_row['enable_auditlog']:
        print("Auditlog has been disabled. Ok, let's check setting of environmental variable DD_ENABLE_AUDITLOG.")
        if settings.ENABLE_AUDITLOG:
            print("Misconfiguration detected")
            exit(47)
        else:
            print("It was disabled as well so we are good.")
    else:
        print("Auditlog has not been disabled. Good, we can continue.")
else:
    print("Database has been already migrated. Nothing to check.")
EOD
then
  echo "You have set 'enable_auditlog' to False in the past. It is not possible to manage auditlog in System settings anymore. If you would like to keep auditlog disabled, you need to set environmental variable DD_ENABLE_AUDITLOG to False for all Django containers (uwsgi, celeryworker & initializer)."
  echo "Or there is some other error in checking script. Check logs of this container."
  exit 47
fi

echo "Making migrations"
python3 manage.py makemigrations dojo
echo "Migrating"
python3 manage.py migrate

echo "Admin user: ${DD_ADMIN_USER}"
ADMIN_EXISTS=$(echo "SELECT * from auth_user;" | python manage.py dbshell | grep "${DD_ADMIN_USER}")
# Abort if the admin user already exists, instead of giving a new fake password that won't work
if [ -n "$ADMIN_EXISTS" ]
then
    echo "Admin password: Initialization detected that the admin user ${DD_ADMIN_USER} already exists in your database."
    echo "If you don't remember the ${DD_ADMIN_USER} password, you can create a new superuser with:"
    echo "$ docker compose exec uwsgi /bin/bash -c 'python manage.py createsuperuser'"
    create_announcement_banner
    initialize_data
    exit
fi

if [ -z "${DD_ADMIN_PASSWORD}" ]
then
  DD_ADMIN_PASSWORD="$(LC_ALL=C tr -dc a-zA-Z0-9 < /dev/urandom | \
    head -c 22)"
  export DD_ADMIN_PASSWORD
  echo "Admin password: ${DD_ADMIN_PASSWORD}"
fi

if [ -z "${DD_JIRA_WEBHOOK_SECRET}" ]
then
  DD_JIRA_WEBHOOK_SECRET="$(uuidgen)"
  export DD_JIRA_WEBHOOK_SECRET
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
       language_type objects_review regulation initial_surveys role sla_configurations

  echo "UPDATE dojo_system_settings SET jira_webhook_secret='$DD_JIRA_WEBHOOK_SECRET'" | python manage.py dbshell

  echo "Importing extra fixtures"
  # If there is extra fixtures, load them
  for i in $(find dojo/fixtures/extra_*.json | sort -n 2>/dev/null) ; do
    echo "Loading $i"
    python3 manage.py loaddata "${i%.*}"
  done

  echo "Installing watson search index"
  python3 manage.py installwatson

  # surveys fixture needs to be modified as it contains an instance dependant polymorphic content id
  echo "Migration of textquestions for surveys"
  python3 manage.py migrate_textquestions

  create_announcement_banner
  initialize_data
fi
