#!/bin/bash

# The entrypoint for regular image (from Dockerfile.update)
# Author: Alexander Tyutin <alexander@tyutin.net> https://github.com/AlexanderTyutin

DD_DEBUG=true
DD_ALLOWED_HOSTS=*

service mysql start

cd /opt/dojo
source ./bin/activate
cd django-DefectDojo
git checkout dev

python3 manage.py runserver 0.0.0.0:8000
