Running in Production
=====================

This guide will walk you through how to setup DefectDojo for running in production using Ubuntu 16.04, MySQL, nginx, and uwsgi.

**Install Required Packages**

.. code-block:: console

  sudo apt-get install python-pip nginx mysql-server

**Create MySQL Database and User**

.. code-block:: console

  mysql -u root -p

  mysql> create user 'dojo'@'localhost' identified by '<password>';

  mysql> create database defectdojo;

  mysql> grant all privileges on defectdojo.* to 'dojo'@'localhost';

  mysql> flush privileges;

  mysql> quit

*Install, Setup, and Activate Virtualenv*

.. code-block:: console

  pip install virtualenv

  virtualenv dojo

  source dojo/bin/activate

**Install Dojo**

.. code-block:: console

  cd django-DefectDojo

  ./setup.bash

**Install Uwsgi**

.. code-block:: console

  pip install uwsgi

**Install WKHTML**

from inside the django-DefectDojo/ directory execute:

.. code-block:: console

  ./reports.sh

**Disable Debugging**

Using the text-editor of your choice, change ``DEBUG`` in django-DefectDojo/dojo/settings.py to:

.. code-block:: console

  `DEBUG = False` 

**Start Celery and Beats**

From inside the django-DefectDojo/ directory execute:

.. code-block:: console

  celery -A dojo worker -l info --concurrency 3

  celery beat -A dojo -l info

It is recommended that you daemonized both these processes with the sample configurations found `here`_ and `here.`_

.. _here: https://github.com/celery/celery/blob/3.1/extra/supervisord/celeryd.conf
.. _here.: https://github.com/celery/celery/blob/3.1/extra/supervisord/celerybeat.conf

However, for a quick setup you can use the following to run both in the background

.. code-block:: console

  celery -A dojo worker -l info --concurrency 3 &

  celery beat -A dojo -l info &

*Start Uwsgi*

From inside the django-DefectDojo/ directory execute:

.. code-block:: console

  uwsgi --socket :8001 --wsgi-file wsgi.py --workers 7

It is recommended that you use an Upstart job or a @restart cron job to launch uwsgi on reboot. However, if you’re in a hurry you can use the following to run it in the background:

.. code-block:: console

  uwsgi --socket :8001 --wsgi-file wsgi.py --workers 7 &

*NGINX Configuration*

Everyone feels a little differently about nginx settings, so here are the barebones to add your to your nginx configuration to proxy uwsgi. Make sure to modify the filesystem paths if needed:

.. code-block:: json

  upstream django {
    server 127.0.0.1:8001; 
  }

  server {
    listen 80;
    location /static/ {
        alias   /data/prod_dojo/django-DefectDojo/static/;
    }

    location /media/ {
        alias   /data/prod_dojo/django-DefectDojo/media/;
    }

    location / {
        uwsgi_pass django;
        include     /data/prod_dojo/django-DefectDojo/wsgi_params;
    }
  }

*That's it!*
