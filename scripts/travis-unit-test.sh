#!/usr/bin/env bash
# Run available unittests with a simple setup

set -ex

pip install virtualenv
virtualenv ~/dojo-venv

cp ./dojo/settings/settings.dist.py ./dojo/settings/settings.py

source ~/dojo-venv/bin/activate

pip install -r requirements.txt

export DJANGO_SETTINGS_MODULE=dojo.settings.unittest

python manage.py makemigrations dojo
python manage.py migrate
python manage.py test dojo.unittests

deactivate

rm ./dojo/settings/settings.py

set +ex
