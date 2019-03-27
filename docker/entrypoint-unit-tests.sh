#!/bin/sh
# Run available unittests with a simple setup

cd /app
python manage.py makemigrations dojo
python manage.py migrate
exec python manage.py test dojo.unittests --keepdb
