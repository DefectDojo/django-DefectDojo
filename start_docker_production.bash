#!/usr/bin/env bash 
celery -A dojo worker -l info --concurrency 3
celery beat -A dojo -l info
uwsgi --socket :8001 --wsgi-file wsgi.py --workers 7
