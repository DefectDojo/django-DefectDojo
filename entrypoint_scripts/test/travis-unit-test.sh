#!/usr/bin/env bash
# Run available unittests with a simple setup

set -ex

pip install virtualenv
virtualenv ~/dojo-venv

source ~/dojo-venv/bin/activate

pip install -r requirements.txt

export DJANGO_SETTINGS_MODULE=dojo.settings.unittest
export DD_SECRET_KEY=`cat /dev/urandom | LC_CTYPE=C tr -dc "a-zA-Z0-9" | head -c 128`
export DD_CREDENTIAL_AES_256_KEY=`cat /dev/urandom | LC_CTYPE=C tr -dc "a-zA-Z0-9" | head -c 128`
export DD_DATABASE_URL="sqlite:///test.db"
export DD_DEBUG=on

python manage.py makemigrations dojo
python manage.py migrate
python manage.py test dojo.unittests

deactivate

set +ex
