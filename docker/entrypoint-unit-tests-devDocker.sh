#!/bin/sh
# Run available unittests with a simple setup
umask 0002

cd /app
# Unset the database URL so that we can force the DD_TEST_DATABASE_NAME (see django "DATABASES" configuration in settings.dist.py)
unset DD_DATABASE_URL

python3 manage.py makemigrations dojo
python3 manage.py migrate

python3 manage.py test dojo.unittests --keepdb

echo "End of tests. Leaving the container up"
tail -f /dev/null
