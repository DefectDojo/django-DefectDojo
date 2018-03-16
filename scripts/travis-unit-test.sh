#!/usr/bin/env bash
# Run available unittests with a simple setup

set -ex

# Install and source a virtualenv
pip install virtualenv
virtualenv ~/dojo-venv
source ~/dojo-venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Bring the app up and running
export DJANGO_SETTINGS_MODULE=dojo.settings.unittest

python manage.py migrate
python manage.py test dojo.unittests

set +ex
