#!/usr/bin/env bash
# Run available unittests with a simple setup
cd /app
python manage.py makemigrations dojo
python manage.py migrate
python manage.py test dojo.unittests -v 2
