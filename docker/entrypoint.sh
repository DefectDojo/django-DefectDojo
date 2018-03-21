#!/bin/bash

chown -R mysql:mysql /var/lib/mysql /var/run/mysqld
service mysql start
su - dojo 
cd /opt/django-DefectDojo
celery -A dojo worker -l info --concurrency 3 >> worker.log 2>&1 &
celery beat -A dojo -l info  >> beat.log 2>&1 &
python manage.py runserver 0.0.0.0:8000 >> dojo.log 2>&1	