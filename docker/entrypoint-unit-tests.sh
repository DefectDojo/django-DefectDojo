#!/bin/sh
# Run available unittests with a setup for CI/CD:
# - Fail if migrations are not created
# - Exit container after running tests to allow exit code to propagate as test result
set -x
set -e
set -v

cd /app
# Unset the database URL so that we can force the DD_TEST_DATABASE_NAME (see django "DATABASES" configuration in settings.dist.py)
unset DD_DATABASE_URL

TARGET_SETTINGS_FILE=dojo/settings/settings.py
if [ ! -f ${TARGET_SETTINGS_FILE} ]; then
  echo "Creating settings.py"
  cp dojo/settings/settings.dist.py dojo/settings/settings.py
fi

python3 manage.py makemigrations --no-input --check --dry-run --verbosity 3 || {
    cat <<-EOF

********************************************************************************

You made changes to the models without creating a DB migration for them.

**NEVER** change existing migrations, create a new one.

If you're not familiar with migrations in Django, please read the
great documentation thoroughly:
https://docs.djangoproject.com/en/1.11/topics/migrations/

********************************************************************************

EOF
    exit 1
}

python3 manage.py migrate

python3 manage.py test dojo.unittests -v 3 --no-input
