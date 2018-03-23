#!/bin/bash

chown -R mysql:mysql /var/lib/mysql /var/run/mysqld
service mysql start

cd /opt/django-DefectDojo
su - dojo -c "cd /opt/django-DefectDojo && celery -A dojo worker -l info --concurrency 3 >> /opt/django-DefectDojo/worker.log 2>&1 &" \
&& su - dojo -c "cd /opt/django-DefectDojo && celery beat -A dojo -l info  >> /opt/django-DefectDojo/beat.log 2>&1 &" \
&& su - dojo -c "cd /opt/django-DefectDojo && python manage.py runserver 0.0.0.0:8000 >> /opt/django-DefectDojo/dojo.log 2>&1"
