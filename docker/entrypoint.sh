#!/bin/sh

# Waits for the database to come up.
./docker/wait-for-it.sh $DD_DATABASE_HOST:$DD_DATABASE_PORT

if [ -z "$DD_DATABASE_URL" ]; then
  if [ -z "$DD_DATABASE_PASSWORD" ]; then
      echo "Please set DD_DATABASE_URL or other DD_DATABASE_HOST, DD_DATABASE_USER, DD_DATABASE_PASSWORD, ..."
      exit 1
  fi
  export DD_DATABASE_URL="$DD_DATABASE_TYPE://$DD_DATABASE_USER:$DD_DATABASE_PASSWORD@$DD_DATABASE_HOST:$DD_DATABASE_PORT/$DD_DATABASE_NAME"
fi

if [ ! -f "/opt/django-DefectDojo/static/docker_complete" ]; then
  python manage.py makemigrations dojo
  python manage.py makemigrations --merge --noinput
  python manage.py migrate

  if [ -z "$DD_ADMIN_PASSWORD" ]; then
      DD_ADMIN_PASSWORD="admin"
  fi

  # The '&&' is critical here. If the admin user is already created, setting the
  # password will not be done.
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
  touch /opt/django-DefectDojo/static/docker_complete
fi

gunicorn \
    --env DJANGO_SETTINGS_MODULE=dojo.settings.settings \
    dojo.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 3 &
celery -A dojo worker -l info --concurrency 3
