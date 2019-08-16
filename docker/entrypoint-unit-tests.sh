#!/bin/sh
# Run available unittests with a simple setup
umask 0002

cd /app

./manage.py makemigrations --no-input --check --dry-run || {
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

./manage.py migrate

exec ./manage.py test dojo.unittests
