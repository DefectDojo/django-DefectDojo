#!/bin/sh
# Run available unittests with a simple setup

# Make sure to exit early on errors, for example if the settings file cannot be created.
# set -e
set -x
echo "entrypoint unit tests dev docker"
umask 0002

cd /app
ls -al
ls -al dojo/
ls -al dojo/settings/
whoami
id

# Unset the database URL so that we can force the DD_TEST_DATABASE_NAME (see django "DATABASES" configuration in settings.dist.py)
unset DD_DATABASE_URL

cd /app
TARGET_SETTINGS_FILE=dojo/settings/settings.py
if [ ! -f ${TARGET_SETTINGS_FILE} ]; then
  echo "Creating settings.py"
  cp dojo/settings/settings.dist.py dojo/settings/settings.py
else
  echo "settings.py already present, not creating a new one"
fi

cat dojo/settings/settings.py

echo "checking migrations"
python3 manage.py makemigrations dojo
echo "running migrations"
python3 manage.py migrate

echo "running unit tests"
python3 manage.py test dojo.unittests.test_apiv2_scan_import_options --keepdb -v 2

echo "End of tests. Leaving the container up"
tail -f /dev/null
