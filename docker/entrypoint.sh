#!/bin/sh

/wait-for-it.sh $DEFECT_DOJO_DEFAULT_DATABASE_HOST:$DEFECT_DOJO_DEFAULT_DATABASE_PORT

python manage.py makemigrations dojo
python manage.py makemigrations --merge --noinput
python manage.py migrate

if [ ! -z "$DEFECT_DOJO_ADMIN_PASSWORD" ]; then
    DEFECT_DOJO_ADMIN_PASSWORD="admin"
fi

python manage.py createsuperuser \
    --noinput \
    --username=admin \
    --email='admin@localhost' && \
    ./docker/setup-superuser.expect

python manage.py loaddata product_type
python manage.py loaddata test_type
python manage.py loaddata development_environment
python manage.py loaddata system_settings
python manage.py loaddata benchmark_type
python manage.py loaddata benchmark_category
python manage.py loaddata benchmark_requirement
python manage.py loaddata language_type
python manage.py loaddata objects_review
python manage.py loaddata regulation
python manage.py installwatson
python manage.py buildwatson
python manage.py collectstatic --noinput

if [ ! -z "$DEFECT_DOJO_DEBUG" ] && [ "$DEFECT_DOJO_DEBUG" = "true" ]; then
    echo "Starting manage.py in dev mode"
    DJANGO_SETTINGS_MODULE=dojo.settings.settings python manage.py runserver 0.0.0.0:8000
else
    gunicorn \
        --env DJANGO_SETTINGS_MODULE=dojo.settings.settings \
        dojo.wsgi:application \
        --bind 0.0.0.0:8000 \
        --workers 3

fi
celery -A dojo worker -l info --concurrency 3
