Running in Production
=====================

This guide will walk you through how to setup DefectDojo for running in production using Ubuntu 16.04, nginx, and uwsgi.

**Install, Setup, and Activate Virtualenv**

Assumes running as root or using sudo command for the below.

.. code-block:: console

  pip install virtualenv

  cd /opt
  
  virtualenv dojo
  
  cd /opt/dojo
  
  git clone https://github.com/DefectDojo/django-DefectDojo.git
  
  useradd -m dojo
  
  chown -R dojo /opt/dojo

  source ./bin/activate

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

Using the text-editor of your choice, change ``DEBUG`` in django-DefectDojo/dojo/settings/settings.py to:

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

**Start Uwsgi**

From inside the django-DefectDojo/ directory execute:

.. code-block:: console

  uwsgi --socket :8001 --wsgi-file wsgi.py --workers 7

It is recommended that you use an Upstart job or a @restart cron job to launch uwsgi on reboot. However, if you’re in a hurry you can use the following to run it in the background:

.. code-block:: console

  uwsgi --socket :8001 --wsgi-file wsgi.py --workers 7 &

**Making Defect Dojo start on boot**

Below we configure service files for systemd.  The commands follow, the config files are below the Nginx in the next section.

.. code-block:: console

  cd /etc/systemd/system/
  
  vi dojo.service
    [contents below]
  
  systemctl enable dojo
  
  systemctl start dojo
  
  systemctl status dojo
    [ensure it launched OK]
  
  vi celery-worker.service
    [contents below]
  
  systemctl enable celery-worker
  
  systemctl start celery-worker
  
  systemctl status celery-worker
    [ensure it launched OK]
  
  vi celery-beat.service
    [contents below]
  
  systemctl enable celery-beat
  
  systemctl start celery-beat
  
  systemctl status celery-beat
    [ensure it launched OK]
  

*NGINX Configuration*

Everyone feels a little differently about nginx settings, so here are the barebones to add your to your nginx configuration to proxy uwsgi. Make sure to modify the filesystem paths if needed:

.. code-block:: json

  upstream django {
    server 127.0.0.1:8001; 
  }
  
  server {
    listen 80;
    return 301 https://$host$request_uri;
  }

  server {
    listen 443;
    server_name <YOUR_SERVER_NAME>;
    
    client_max_body_size 500m; # To accommodate large scan files
    
    ssl_certificate           <PATH_TO_CRT>;
    ssl_certificate_key       <PATH_TO_KEY>;
    
    ssl on;
    
    <YOUR_SSL_SETTINGS> # ciphers, options, logging, etc
    
    location /static/ {
        alias   <PATH_TO_DOJO>/django-DefectDojo/static/;
    }

    location /media/ {
        alias   <PATH_TO_DOJO>/django-DefectDojo/media/;
    }

    location / {
        uwsgi_pass django;
        include     <PATH_TO_DOJO>/django-DefectDojo/wsgi_params;
    }
  }

*Systemd Configuration Files*

dojo.service

.. code-block:: console

  [Unit]
  Description=uWSGI instance to serve DefectDojo
  Requires=nginx.service mysql.service
  Before=nginx.service
  After=mysql.service
  
  [Service]
  ExecStart=/bin/bash -c 'su - dojo -c "cd /opt/dojo/django-DefectDojo && source ../bin/activate && uwsgi --socket :8001 --wsgi-file wsgi.py --workers 7"'
  Restart=always
  RestartSec=3
  #StandardOutput=syslog 
  #StandardError=syslog  
  SyslogIdentifier=dojo
  
  [Install]
  WantedBy=multi-user.target

celery-worker.service

.. code-block:: console

  [Unit]
  Description=celery workers for DefectDojo
  Requires=dojo.service
  After=dojo.service
  
  [Service]
  ExecStart=/bin/bash -c 'su - dojo -c "cd /opt/dojo/django-DefectDojo && source ../bin/activate && celery -A dojo worker -l info --concurrency 3"'
  Restart=always
  RestartSec=3
  #StandardOutput=syslog 
  #StandardError=syslog  
  SyslogIdentifier=celeryworker
  
  [Install]
  WantedBy=multi-user.target

celery-beat.service

.. code-block:: console

  [Unit]
  Description=celery beat for DefectDojo
  Requires=dojo.service
  After=dojo.service
  
  [Service]
  ExecStart=/bin/bash -c 'su - dojo -c "cd /opt/dojo/django-DefectDojo && source ../bin/activate && celery beat -A dojo -l info"'
  Restart=always
  RestartSec=3
  #StandardOutput=syslog 
  #StandardError=syslog  
  SyslogIdentifier=celerybeat
  
  [Install]
  WantedBy=multi-user.target


*That's it!*
