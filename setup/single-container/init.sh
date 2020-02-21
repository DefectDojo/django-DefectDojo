#!/bin/bash

# The entrypoint for Dockerfile.create
# Author: Alexander Tyutin <alexander@tyutin.net> https://github.com/AlexanderTyutin

apt-get update
apt-get install -y python3-pip git

pip3 install virtualenv

cd /opt

virtualenv dojo

cd dojo/

git clone https://github.com/DefectDojo/django-DefectDojo.git
git checkout dev

useradd -m dojo
cd /opt
chown -R dojo /opt/dojo
cd dojo
source ./bin/activate
cd django-DefectDojo
git checkout dev
cd setup

./setup.bash -n

DD_DEBUG=true
DD_ALLOWED_HOSTS=*

service mysql start

cd /opt/dojo
source ./bin/activate
cd django-DefectDojo
git checkout dev

python3 manage.py runserver 0.0.0.0:8000
